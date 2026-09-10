//! Read-cache continuity for an open file (MS-SMB2 2.2.13.2.8).
//!
//! A receipt is useful only while its original open and connection survive.
//! A break is terminal, including a break racing the CREATE response. This
//! deliberately does not reclaim leases or use timestamps as content versions.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use super::connection::Connection;
use crate::msg::create_context::{self, CreateContext};
use crate::pack::{Pack, ReadCursor, WriteCursor};
use crate::types::{Command, OplockLevel, TreeId};
use crate::{Error, Result};

const PENDING: u8 = 0;
const GRANTED: u8 = 1;
const INVALID: u8 = 2;
const NAME: &[u8] = b"RqLs";

// All connections share ClientGuid. A server may send a break on ANY of
// them, so a connection-local registry would silently miss invalidations.
fn registry() -> &'static Mutex<HashMap<[u8; 16], Weak<LeaseState>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<[u8; 16], Weak<LeaseState>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

struct LeaseState {
    key: [u8; 16],
    state: AtomicU8,
    conn: Connection,
    generation: u64,
    tree: TreeId,
}

/// An unforgeable, process-local receipt for an uninterrupted read lease.
/// It proves cache continuity, not namespace identity or application consistency.
#[derive(Clone)]
pub struct ReadLeaseProof(Arc<LeaseState>);

impl ReadLeaseProof {
    /// Opaque receipt identifier. Persisting it does not persist its validity.
    pub fn token(&self) -> [u8; 16] {
        self.0.key
    }

    /// False after any break, close, transport loss, or connection revival.
    pub fn is_valid(&self) -> bool {
        self.0.state.load(Ordering::Acquire) == GRANTED
            && !self.0.conn.is_disconnected()
            && self.0.conn.generation() == self.0.generation
    }
}

/// Owned by the open, never by a cached receipt. Drop invalidates receipts.
pub(crate) struct ReadLeaseRegistration(ReadLeaseProof);

impl ReadLeaseRegistration {
    pub(crate) fn new(conn: &Connection, tree: TreeId) -> Self {
        let mut key = [0; 16];
        getrandom::fill(&mut key).expect("read lease key randomness unavailable");
        let state = Arc::new(LeaseState {
            key,
            state: AtomicU8::new(PENDING),
            conn: conn.clone(),
            generation: conn.generation(),
            tree,
        });
        registry()
            .lock()
            .unwrap()
            .insert(key, Arc::downgrade(&state));
        Self(ReadLeaseProof(state))
    }

    pub(crate) fn context(&self) -> Vec<u8> {
        let mut data = Vec::from(self.0 .0.key);
        data.extend_from_slice(&1u32.to_le_bytes()); // READ caching only
        data.resize(32, 0); // flags and duration reserved
        create_context::pack_contexts(&[CreateContext::new(NAME, data)])
    }

    pub(crate) fn grant(&self, level: OplockLevel, bytes: &[u8]) -> Result<()> {
        let contexts = create_context::parse_contexts(bytes)?;
        let matches: Vec<_> = contexts.iter().filter(|c| c.name == NAME).collect();
        if level != OplockLevel::Lease || matches.is_empty() {
            self.invalidate();
            return Ok(());
        }
        if matches.len() != 1 || matches[0].data.len() != 32 {
            self.invalidate();
            return Err(Error::invalid_data("invalid read lease grant"));
        }
        let data = &matches[0].data;
        let state = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let flags = u32::from_le_bytes(data[20..24].try_into().unwrap());
        if data[..16] != self.0 .0.key || state != 1 || flags != 0 {
            self.invalidate();
            return Ok(());
        }
        // NEVER resurrect a receipt invalidated before CREATE was routed.
        let _ =
            self.0
                 .0
                .state
                .compare_exchange(PENDING, GRANTED, Ordering::AcqRel, Ordering::Acquire);
        Ok(())
    }

    pub(crate) fn proof(&self) -> Option<ReadLeaseProof> {
        self.0.is_valid().then(|| self.0.clone())
    }

    fn invalidate(&self) {
        self.0 .0.state.store(INVALID, Ordering::Release);
    }
}

impl Drop for ReadLeaseRegistration {
    fn drop(&mut self) {
        self.invalidate();
        registry().lock().unwrap().remove(&self.0 .0.key);
    }
}

/// Losing any receive channel creates uncertainty: the server may have sent
/// another connection's break there. Fail closed for this client's receipts.
pub(crate) fn invalidate_server(server: Option<crate::pack::Guid>) {
    for state in registry()
        .lock()
        .unwrap()
        .values()
        .filter_map(Weak::upgrade)
    {
        if state.conn.params().map(|p| p.server_guid) == server {
            state.state.store(INVALID, Ordering::Release);
        }
    }
}

struct LeaseAck([u8; 16]);
impl Pack for LeaseAck {
    fn pack(&self, c: &mut WriteCursor) {
        c.write_u16_le(36);
        c.write_u16_le(0);
        c.write_u32_le(0);
        c.write_bytes(&self.0);
        c.write_u32_le(0); // relinquish everything
        c.write_u64_le(0);
    }
}

/// Called synchronously by the sole receiver BEFORE routing any replies.
pub(crate) fn receive_break(bytes: &[u8], server: Option<crate::pack::Guid>) -> Result<()> {
    let mut c = ReadCursor::new(bytes);
    if c.read_u16_le()? != 44 || bytes.len() != 44 {
        invalidate_server(server);
        return Err(Error::invalid_data("invalid lease break size"));
    }
    let _epoch = c.read_u16_le()?;
    let flags = c.read_u32_le()?;
    let key: [u8; 16] = c.read_bytes(16)?.try_into().unwrap();
    let _current = c.read_u32_le()?;
    let _new = c.read_u32_le()?;
    let state = registry().lock().unwrap().get(&key).and_then(Weak::upgrade);
    if let Some(state) = state.filter(|s| s.conn.params().map(|p| p.server_guid) == server) {
        state.state.store(INVALID, Ordering::Release);
        if flags & 1 != 0 {
            // The reader task must remain free to receive the ACK response.
            tokio::spawn(async move {
                let result = state
                    .conn
                    .execute(Command::OplockBreak, &LeaseAck(key), Some(state.tree))
                    .await;
                if result.is_err() {
                    invalidate_server(server);
                }
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::connection::pack_message;
    use crate::msg::header::Header;
    use crate::transport::MockTransport;
    use crate::types::MessageId;

    fn setup() -> (Arc<MockTransport>, Connection) {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "read-lease-test",
        );
        conn.set_test_params(super::super::connection::NegotiatedParams {
            dialect: crate::types::Dialect::Smb2_1,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: super::super::connection::random_guid(),
            signing_required: false,
            capabilities: crate::types::flags::Capabilities::new(
                crate::types::flags::Capabilities::LEASING,
            ),
            gmac_negotiated: false,
            cipher: None,
            compression_supported: false,
        });
        conn.set_credits(32);
        (mock, conn)
    }

    fn break_body(key: [u8; 16], ack: bool) -> Vec<u8> {
        let mut c = WriteCursor::new();
        c.write_u16_le(44);
        c.write_u16_le(0);
        c.write_u32_le(u32::from(ack));
        c.write_bytes(&key);
        c.write_u32_le(1);
        c.write_u32_le(0);
        c.write_bytes(&[0; 12]);
        c.into_inner()
    }

    #[tokio::test]
    async fn read_lease_break_before_grant_never_resurrects_receipt() {
        let (_mock, conn) = setup();
        let registration = ReadLeaseRegistration::new(&conn, TreeId(7));
        receive_break(
            &break_body(registration.0.token(), false),
            conn.params().map(|p| p.server_guid),
        )
        .unwrap();
        registration
            .grant(OplockLevel::Lease, &registration.context())
            .unwrap();
        assert!(registration.proof().is_none());
    }

    #[tokio::test]
    async fn read_lease_drop_invalidates_cloned_receipts() {
        let (_mock, conn) = setup();
        let registration = ReadLeaseRegistration::new(&conn, TreeId(7));
        registration
            .grant(OplockLevel::Lease, &registration.context())
            .unwrap();
        let proof = registration.proof().unwrap();
        assert!(proof.is_valid());
        drop(registration);
        assert!(!proof.is_valid());
    }

    #[tokio::test]
    async fn read_lease_receiver_invalidates_without_any_pending_request() {
        let (mock, conn) = setup();
        let registration = ReadLeaseRegistration::new(&conn, TreeId(7));
        registration
            .grant(OplockLevel::Lease, &registration.context())
            .unwrap();
        let proof = registration.proof().unwrap();
        let mut h = Header::new_request(Command::OplockBreak);
        h.flags.set_response();
        h.message_id = MessageId::UNSOLICITED;
        struct Body(Vec<u8>);
        impl Pack for Body {
            fn pack(&self, c: &mut WriteCursor) {
                c.write_bytes(&self.0);
            }
        }
        mock.queue_response(pack_message(&h, &Body(break_body(proof.token(), false))));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while proof.is_valid() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            mock.sent_count(),
            0,
            "read-only break without ACK_REQUIRED needs no ACK"
        );
    }

    #[tokio::test]
    async fn read_lease_transport_loss_invalidates_receipt() {
        let (mock, conn) = setup();
        let registration = ReadLeaseRegistration::new(&conn, TreeId(7));
        registration
            .grant(OplockLevel::Lease, &registration.context())
            .unwrap();
        let proof = registration.proof().unwrap();
        mock.close();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while proof.is_valid() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn read_lease_create_wire_roundtrip_and_early_break() {
        use crate::client::test_helpers::build_create_response_with_contexts;
        use crate::msg::create::CreateRequest;
        use crate::pack::Unpack;
        use crate::types::FileId;
        for early_break in [false, true] {
            let (mock, conn) = setup();
            let server = conn.params().map(|p| p.server_guid);
            let tree = Arc::new(super::super::tree::Tree {
                tree_id: TreeId(7),
                share_name: "test".into(),
                server: "read-lease-test".into(),
                is_dfs: false,
                encrypt_data: false,
            });
            let token = tree.path_token("data.bin");
            let task = tokio::spawn(async move {
                super::super::stream::open_file_reader_leased_token(tree, conn, &token).await
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while mock.sent_count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let sent = mock.sent_message(0).unwrap();
            let request = CreateRequest::unpack(&mut ReadCursor::new(&sent[64..])).unwrap();
            assert_eq!(request.requested_oplock_level, OplockLevel::Lease);
            let contexts = create_context::parse_contexts(&request.create_contexts).unwrap();
            assert_eq!(contexts.len(), 1);
            assert_eq!(&contexts[0].data[16..20], &1u32.to_le_bytes());
            let key = contexts[0].data[..16].try_into().unwrap();
            if early_break {
                receive_break(&break_body(key, false), server).unwrap();
            }
            let mut response = build_create_response_with_contexts(
                FileId {
                    persistent: 1,
                    volatile: 2,
                },
                123,
                &contexts,
            );
            response[66] = OplockLevel::Lease as u8;
            mock.queue_response(response);
            let reader = task.await.unwrap().unwrap();
            assert_eq!(reader.read_lease_proof().is_some(), !early_break);
            drop(reader);
            mock.close();
        }
    }

    #[tokio::test]
    async fn read_lease_other_connection_receives_break_and_ack_uses_owner_tree() {
        let (mock, conn) = setup();
        let registration = ReadLeaseRegistration::new(&conn, TreeId(42));
        registration
            .grant(OplockLevel::Lease, &registration.context())
            .unwrap();
        let proof = registration.proof().unwrap();
        let (other_mock, mut other_conn) = setup();
        other_conn.set_test_params(conn.params().unwrap());
        let mut h = Header::new_request(Command::OplockBreak);
        h.flags.set_response();
        h.message_id = MessageId::UNSOLICITED;
        struct Body(Vec<u8>);
        impl Pack for Body {
            fn pack(&self, c: &mut WriteCursor) {
                c.write_bytes(&self.0);
            }
        }
        other_mock.queue_response(pack_message(&h, &Body(break_body(proof.token(), true))));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while mock.sent_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!proof.is_valid(), "invalidation must precede ACK");
        let ack = mock.sent_message(0).unwrap();
        assert_eq!(u32::from_le_bytes(ack[36..40].try_into().unwrap()), 42);
        assert_eq!(other_mock.sent_count(), 0);
        mock.close();
        other_mock.close();
    }
    #[test]
    fn ack_wire_shape_relinquishes_all_caching() {
        let mut c = WriteCursor::new();
        LeaseAck([7; 16]).pack(&mut c);
        let bytes = c.into_inner();
        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[8..24], &[7; 16]);
        assert_eq!(&bytes[24..], &[0; 12]);
    }
    #[test]
    fn malformed_break_is_rejected() {
        assert!(receive_break(&[0; 44], None).is_err());
        assert!(receive_break(&44u16.to_le_bytes(), None).is_err());
    }
}
