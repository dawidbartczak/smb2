//! Connection-wide SMB2 credit accounting.
//!
//! A server hands the client a budget ("credits") and every request spends
//! from it: `CreditCharge = ceil(max(SendPayload, ExpectedResponse) / 65536)`,
//! at least 1 (MS-SMB2 § 3.1.5.2). Responses carry a `CreditResponse` grant
//! that puts credits back. A client that sends more than it holds is in
//! violation, and MS-SMB2 § 3.3.1.1 lets the server drop the connection —
//! some servers instead stop answering while the TCP socket stays open, which
//! looks exactly like a hung client.
//!
//! The budget is per *connection*, so it lives here rather than in any one
//! stream: several pipelined transfers over one connection draw on the same
//! pool.
//!
//! **Credits are spent on send, not on receipt.** That is the whole point of
//! this type. Accounting for a request only once its answer arrives leaves
//! everything currently in flight invisible, and concurrent senders each read
//! the same "plenty available" number and pile on.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;

/// The window the client steers the server toward, in credits.
///
/// Every request asks for its own charge back plus whatever is needed to reach
/// this number, so an idle connection asks for little and a saturated one asks
/// for a lot. 512 credits is comfortably more than the deepest pipeline this
/// crate opens (32 requests at 8 credits each for 512 KB chunks), leaving room
/// for other work on the same connection. Servers clamp the request to their
/// own maximum, so asking high is safe; asking low is not, because a window
/// that shrinks to nothing serializes every transfer.
const CREDIT_TARGET: u16 = 512;

/// Default bound on how long a send waits for the server to grant credits
/// before giving up with [`Error::CreditStarvation`](crate::Error::CreditStarvation).
///
/// Long enough that a merely busy server is never mistaken for a dead one,
/// short enough that a silent one surfaces as an error instead of a hang.
pub(crate) const DEFAULT_CREDIT_WAIT: Duration = Duration::from_secs(30);

/// Scheduling class for a request waiting on SMB credits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreditClass {
    /// Standalone CLOSE requests, which must not be blocked by a large READ.
    Control,
    /// All ordinary and compound requests.
    Data,
}

#[derive(Debug)]
pub(crate) struct CreditPoolClosed;

const WAITER_PENDING: u8 = 0;
const WAITER_GRANTED: u8 = 1;
const WAITER_FAILED: u8 = 2;
const WAITER_CONSUMED: u8 = 3;
const WAITER_CANCELLED: u8 = 4;

struct CreditWaiter {
    id: u64,
    charge: u16,
    state: Arc<AtomicU8>,
    ready: oneshot::Sender<Result<(), CreditPoolClosed>>,
}

struct CreditState {
    available: u16,
    closed: bool,
    generation: u64,
    next_waiter_id: u64,
    control: VecDeque<CreditWaiter>,
    data: VecDeque<CreditWaiter>,
}

impl CreditState {
    fn queue_mut(&mut self, class: CreditClass) -> &mut VecDeque<CreditWaiter> {
        match class {
            CreditClass::Control => &mut self.control,
            CreditClass::Data => &mut self.data,
        }
    }

    fn can_reserve_now(&self, charge: u16, class: CreditClass) -> bool {
        if self.closed || self.available < charge {
            return false;
        }

        match class {
            CreditClass::Control => self.control.is_empty(),
            CreditClass::Data => self.control.is_empty() && self.data.is_empty(),
        }
    }

    /// Serve every fitting CLOSE first, then the FIFO head of Data. A Data
    /// waiter can never jump over another Data waiter, even when it is smaller.
    fn dispatch(&mut self) {
        while self
            .control
            .front()
            .is_some_and(|waiter| waiter.charge <= self.available)
        {
            let waiter = self.control.pop_front().expect("front just checked");
            self.available -= waiter.charge;
            waiter.state.store(WAITER_GRANTED, Ordering::Release);
            if waiter.ready.send(Ok(())).is_err() {
                waiter.state.store(WAITER_CANCELLED, Ordering::Release);
                self.available = self.available.saturating_add(waiter.charge);
            }
        }

        if !self.control.is_empty() {
            return;
        }

        while self
            .data
            .front()
            .is_some_and(|waiter| waiter.charge <= self.available)
        {
            let waiter = self.data.pop_front().expect("front just checked");
            self.available -= waiter.charge;
            waiter.state.store(WAITER_GRANTED, Ordering::Release);
            if waiter.ready.send(Ok(())).is_err() {
                waiter.state.store(WAITER_CANCELLED, Ordering::Release);
                self.available = self.available.saturating_add(waiter.charge);
            }
        }
    }

    fn fail_waiters(&mut self) {
        for waiter in self.control.drain(..).chain(self.data.drain(..)) {
            waiter.state.store(WAITER_FAILED, Ordering::Release);
            let _ = waiter.ready.send(Err(CreditPoolClosed));
        }
    }
}

/// Server-granted credits that have not been spent yet.
///
/// Waiters are split into a standalone-CLOSE control queue and an ordinary
/// data queue. Fitting control requests run first; Data remains strictly FIFO.
/// This follows MS-SMB2 § 3.2.4.1.3 and avoids head-of-line blocking a CLOSE
/// behind a READ whose multi-credit charge cannot currently be satisfied.
pub(crate) struct CreditPool {
    state: Mutex<CreditState>,
    /// The reserve deadline in milliseconds, tunable per connection.
    wait_ms: AtomicU64,
}

impl CreditPool {
    /// A fresh pool holds the single credit a client has before NEGOTIATE
    /// (MS-SMB2 § 3.2.5.1.1) — enough to send NEGOTIATE and nothing else.
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(CreditState {
                available: 1,
                closed: false,
                generation: 0,
                next_waiter_id: 0,
                control: VecDeque::new(),
                data: VecDeque::new(),
            }),
            wait_ms: AtomicU64::new(DEFAULT_CREDIT_WAIT.as_millis() as u64),
        }
    }

    /// Throw the spent budget away and start again from the pre-NEGOTIATE
    /// single credit.
    ///
    /// Called when a connection is revived on a new transport. ❌ Don't reuse
    /// the old budget: its permits were granted by a session that no longer
    /// exists, and the new server may have a much smaller window. Carrying
    /// them over would let the first burst after a reconnect out-spend the
    /// server exactly the way the original wedge did.
    pub(crate) fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.fail_waiters();
        state.generation = state.generation.wrapping_add(1);
        state.available = 1;
        state.closed = false;
    }

    /// Credits on hand: granted by the server and not reserved by a request.
    ///
    /// Saturates at `u16::MAX`; no server grants a window that wide.
    pub(crate) fn available(&self) -> u16 {
        self.state.lock().unwrap().available
    }

    /// Bank the `CreditResponse` from a response header.
    pub(crate) fn grant(&self, credits: u16) {
        if credits > 0 {
            let mut state = self.state.lock().unwrap();
            if !state.closed {
                state.available = state.available.saturating_add(credits);
                state.dispatch();
            }
        }
    }

    /// Take `charge` credits if they are on hand right now.
    pub(crate) fn try_reserve(&self, charge: u16, class: CreditClass) -> Option<u64> {
        let charge = charge.max(1);
        let mut state = self.state.lock().unwrap();
        if state.can_reserve_now(charge, class) {
            state.available -= charge;
            Some(state.generation)
        } else {
            None
        }
    }

    /// Wait for `charge` credits. Resolves once they are reserved, or with
    /// `Err` if the pool was closed by a connection teardown.
    ///
    /// Data waiters are FIFO. Standalone CLOSE waiters have their own FIFO and
    /// may use a fitting grant before an unsatisfied multi-credit Data head.
    pub(crate) async fn reserve(
        &self,
        charge: u16,
        class: CreditClass,
    ) -> Result<u64, CreditPoolClosed> {
        let charge = charge.max(1);
        let (ready, mut registration) = {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(CreditPoolClosed);
            }
            if state.can_reserve_now(charge, class) {
                state.available -= charge;
                return Ok(state.generation);
            }

            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let generation = state.generation;
            let waiter_state = Arc::new(AtomicU8::new(WAITER_PENDING));
            let (ready_tx, ready_rx) = oneshot::channel();
            state.queue_mut(class).push_back(CreditWaiter {
                id,
                charge,
                state: Arc::clone(&waiter_state),
                ready: ready_tx,
            });
            (
                ready_rx,
                CreditWaitRegistration {
                    pool: self,
                    id,
                    charge,
                    class,
                    generation,
                    state: waiter_state,
                    armed: true,
                },
            )
        };

        let result = ready.await.unwrap_or(Err(CreditPoolClosed));
        registration.consume(result)
    }

    /// Hand back credits reserved for a request whose bytes never reached the
    /// wire (a signing failure, a transport error). Once the bytes are out,
    /// the credits are the server's and only a grant returns them.
    pub(crate) fn refund(&self, charge: u16, generation: u64) {
        let mut state = self.state.lock().unwrap();
        if !state.closed && state.generation == generation {
            state.available = state.available.saturating_add(charge);
            state.dispatch();
        }
    }

    /// How many credits to request on a request charging `charge`.
    ///
    /// Always at least the charge, so the window can't shrink under a steady
    /// load, plus enough to climb back to [`CREDIT_TARGET`].
    pub(crate) fn request_for(&self, charge: u16) -> u16 {
        charge.saturating_add(CREDIT_TARGET.saturating_sub(self.available()))
    }

    /// How long [`Inner::reserve_credits`](crate::client::connection) waits
    /// before declaring starvation.
    pub(crate) fn wait_timeout(&self) -> Duration {
        Duration::from_millis(self.wait_ms.load(Ordering::Relaxed))
    }

    /// Retune the starvation deadline.
    pub(crate) fn set_wait_timeout(&self, after: Duration) {
        let ms = u64::try_from(after.as_millis()).unwrap_or(u64::MAX);
        self.wait_ms.store(ms, Ordering::Relaxed);
    }

    /// Wake every waiter with an error. Called when the connection dies, so a
    /// task parked on credits fails immediately instead of waiting out the
    /// full deadline for a server that will never answer again.
    pub(crate) fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.generation = state.generation.wrapping_add(1);
        state.fail_waiters();
    }

    /// Whether [`close`](Self::close) has been called.
    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    /// Force the pool to exactly `credits`, for tests that need to stage a
    /// specific window without a full negotiate exchange.
    #[cfg(test)]
    pub(crate) fn set_available(&self, credits: u16) {
        let mut state = self.state.lock().unwrap();
        state.available = credits;
        state.dispatch();
    }
}

struct CreditWaitRegistration<'a> {
    pool: &'a CreditPool,
    id: u64,
    charge: u16,
    class: CreditClass,
    generation: u64,
    state: Arc<AtomicU8>,
    armed: bool,
}

impl CreditWaitRegistration<'_> {
    fn consume(&mut self, result: Result<(), CreditPoolClosed>) -> Result<u64, CreditPoolClosed> {
        let pool = self.pool.state.lock().unwrap();
        let result = if self.belongs_to_current_generation(&pool) {
            if self.state.load(Ordering::Acquire) == WAITER_GRANTED {
                self.state.store(WAITER_CONSUMED, Ordering::Release);
            }
            result.map(|()| self.generation)
        } else {
            self.state.store(WAITER_FAILED, Ordering::Release);
            Err(CreditPoolClosed)
        };
        self.armed = false;
        result
    }

    fn belongs_to_current_generation(&self, pool: &CreditState) -> bool {
        self.generation == pool.generation && !pool.closed
    }
}

impl Drop for CreditWaitRegistration<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let mut pool = self.pool.state.lock().unwrap();
        match self.state.load(Ordering::Acquire) {
            WAITER_PENDING => {
                let removed = if let Some(index) = pool
                    .queue_mut(self.class)
                    .iter()
                    .position(|waiter| waiter.id == self.id)
                {
                    pool.queue_mut(self.class).remove(index);
                    true
                } else {
                    false
                };
                self.state.store(WAITER_CANCELLED, Ordering::Release);
                if removed && self.belongs_to_current_generation(&pool) {
                    pool.dispatch();
                }
            }
            WAITER_GRANTED => {
                if self.belongs_to_current_generation(&pool) {
                    pool.available = pool.available.saturating_add(self.charge);
                }
                self.state.store(WAITER_CANCELLED, Ordering::Release);
                if self.belongs_to_current_generation(&pool) {
                    pool.dispatch();
                }
            }
            WAITER_FAILED | WAITER_CONSUMED | WAITER_CANCELLED => {}
            _ => unreachable!("unknown credit waiter state"),
        }
    }
}

/// Credits taken from the pool for one request that has not been sent yet.
///
/// Dropping without [`commit`](Self::commit) refunds them — that is the path
/// for a request that failed to sign, encrypt, or reach the transport, and for
/// a caller whose future is dropped before the send.
#[must_use = "dropping the reservation refunds the credits without sending"]
pub(crate) struct CreditReservation<'a> {
    pool: Option<&'a CreditPool>,
    charge: u16,
    generation: u64,
}

impl<'a> CreditReservation<'a> {
    pub(crate) fn new(pool: &'a CreditPool, charge: u16, generation: u64) -> Self {
        Self {
            pool: Some(pool),
            charge,
            generation,
        }
    }

    /// The bytes are on the wire: the credits belong to the server now.
    pub(crate) fn commit(mut self) {
        self.pool = None;
    }
}

impl Drop for CreditReservation<'_> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool {
            pool.refund(self.charge, self.generation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_holds_credits_out_of_the_pool_until_it_is_refunded() {
        let pool = CreditPool::new();
        pool.set_available(10);

        let generation = pool
            .try_reserve(4, CreditClass::Data)
            .expect("credits are available");
        assert_eq!(pool.available(), 6);

        let reservation = CreditReservation::new(&pool, 4, generation);
        drop(reservation);
        assert_eq!(
            pool.available(),
            10,
            "an unsent request gives its credits back"
        );
    }

    #[test]
    fn a_committed_reservation_leaves_the_credits_with_the_server() {
        let pool = CreditPool::new();
        pool.set_available(10);

        let generation = pool
            .try_reserve(4, CreditClass::Data)
            .expect("credits are available");
        CreditReservation::new(&pool, 4, generation).commit();

        assert_eq!(
            pool.available(),
            6,
            "credits spent on the wire only come back as a grant"
        );
    }

    #[test]
    fn refund_from_a_retired_generation_does_not_enter_the_new_session() {
        let pool = CreditPool::new();
        pool.set_available(4);
        let generation = pool
            .try_reserve(4, CreditClass::Data)
            .expect("credits are available");
        let reservation = CreditReservation::new(&pool, 4, generation);

        pool.reset();
        drop(reservation);

        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn a_charge_larger_than_the_window_is_not_partially_reserved() {
        let pool = CreditPool::new();
        pool.set_available(3);

        assert!(pool.try_reserve(4, CreditClass::Data).is_none());
        assert_eq!(pool.available(), 3, "a failed reserve takes nothing");
    }

    #[test]
    fn the_credit_request_always_covers_the_charge_and_climbs_to_the_target() {
        let pool = CreditPool::new();

        pool.set_available(0);
        assert_eq!(pool.request_for(8), 8 + CREDIT_TARGET);

        pool.set_available(CREDIT_TARGET);
        assert_eq!(
            pool.request_for(8),
            8,
            "at target, ask only for the charge back"
        );

        pool.set_available(u16::MAX);
        assert_eq!(pool.request_for(8), 8, "never ask for less than the charge");
    }

    #[tokio::test]
    async fn a_grant_wakes_a_waiter() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let waiting = pool.reserve(4, CreditClass::Data);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err(),
            "nothing to reserve yet"
        );

        pool.grant(4);
        waiting.await.expect("the grant satisfies the waiter");
        assert_eq!(pool.available(), 0);
    }

    #[tokio::test]
    async fn closing_the_pool_fails_waiters_instead_of_parking_them() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let waiting = pool.reserve(1, CreditClass::Data);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err()
        );

        pool.close();
        assert!(waiting.await.is_err());
        assert!(pool.is_closed());
    }

    #[tokio::test]
    async fn a_reset_pool_starts_from_one_credit_again_and_is_no_longer_closed() {
        let pool = CreditPool::new();
        pool.set_available(400);
        pool.close();
        assert!(pool.is_closed());

        pool.reset();

        assert!(
            !pool.is_closed(),
            "a revived connection needs a live budget"
        );
        assert_eq!(
            pool.available(),
            1,
            "credits granted by a dead session must not carry over -- the new \
             server's window may be far smaller"
        );
        assert!(pool.try_reserve(1, CreditClass::Data).is_some());
    }

    #[tokio::test]
    async fn a_waiter_on_the_old_budget_is_failed_by_the_reset_rather_than_migrated() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let waiting = pool.reserve(4, CreditClass::Data);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err(),
            "nothing to reserve yet"
        );

        // Teardown, then revival. The waiter belongs to the dead generation.
        pool.close();
        pool.reset();
        pool.grant(64);

        assert!(
            tokio::time::timeout(Duration::from_millis(200), waiting)
                .await
                .expect("the waiter must resolve, not hang")
                .is_err(),
            "a send queued against the old session must fail rather than \
             silently continue on the new one"
        );
    }

    #[tokio::test]
    async fn a_fitting_close_runs_before_an_unsatisfied_multicredit_read() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let data = pool.reserve(4, CreditClass::Data);
        let control = pool.reserve(1, CreditClass::Control);
        tokio::pin!(data, control);
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut data)
            .await
            .is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut control)
                .await
                .is_err()
        );

        pool.grant(1);
        control.await.expect("one credit must be granted to CLOSE");
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut data)
            .await
            .is_err());

        pool.grant(4);
        data.await.expect("the READ runs once its full charge fits");
        assert_eq!(pool.available(), 0);
    }

    #[tokio::test]
    async fn data_waiters_remain_strictly_fifo() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let large = pool.reserve(4, CreditClass::Data);
        let small = pool.reserve(1, CreditClass::Data);
        tokio::pin!(large, small);
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut large)
            .await
            .is_err());
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut small)
            .await
            .is_err());

        pool.grant(1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut small)
                .await
                .is_err(),
            "a small Data request must not jump the queue"
        );

        pool.grant(3);
        large.await.expect("the FIFO head now fits");
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut small)
            .await
            .is_err());
        pool.grant(1);
        small
            .await
            .expect("the second Data waiter follows the head");
    }

    #[tokio::test]
    async fn cancelling_a_waiter_removes_it_without_leaking_credits() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let mut cancelled = Box::pin(pool.reserve(4, CreditClass::Data));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut cancelled)
                .await
                .is_err()
        );
        drop(cancelled);

        let mut next = Box::pin(pool.reserve(1, CreditClass::Data));
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut next)
            .await
            .is_err());
        pool.grant(1);
        next.await
            .expect("the cancelled FIFO head no longer blocks Data");
        assert_eq!(pool.available(), 0);
    }

    #[tokio::test]
    async fn cancelling_an_unfundable_data_head_wakes_the_next_fitting_waiter() {
        let pool = CreditPool::new();
        pool.set_available(1);

        let mut head = Box::pin(pool.reserve(4, CreditClass::Data));
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut head)
            .await
            .is_err());
        let mut next = Box::pin(pool.reserve(1, CreditClass::Data));
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut next)
            .await
            .is_err());

        drop(head);

        next.await
            .expect("removing the blocked FIFO head must dispatch the next waiter");
        assert_eq!(pool.available(), 0);
    }

    #[tokio::test]
    async fn cancelling_after_a_grant_refunds_the_unconsumed_reservation() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let mut cancelled = Box::pin(pool.reserve(4, CreditClass::Data));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut cancelled)
                .await
                .is_err()
        );
        pool.grant(4);
        drop(cancelled);

        assert_eq!(
            pool.available(),
            4,
            "credits granted to a cancelled future must return to the pool"
        );
    }

    #[tokio::test]
    async fn a_grant_not_consumed_before_reset_cannot_cross_sessions() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let mut waiting = Box::pin(pool.reserve(4, CreditClass::Data));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        pool.grant(4);
        pool.reset();

        assert!(waiting.await.is_err());
        assert_eq!(
            pool.available(),
            1,
            "a grant from the retired session must not alter the reset budget"
        );
    }
}
