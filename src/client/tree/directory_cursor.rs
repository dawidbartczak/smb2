//! Owned incremental directory enumeration. A cursor keeps the same server open
//! through all QUERY_DIRECTORY pages; continuation never fabricates FileIndex.
use super::{Connection, DirectoryEntry, FileId, QueryStepOutcome, Result, SmbPathToken, Tree};

/// One opened directory and its enumeration position. Call `close` when stopping
/// early. Successful EOF closes automatically; errors also attempt CLOSE while
/// preserving the enumeration error as the primary cause.
pub struct DirectoryReader {
    tree: Tree,
    connection: Connection,
    token: SmbPathToken,
    file: Option<FileId>,
    restart: bool,
    buffer_len: u32,
    finished: bool,
    close_deadlines: Option<crate::CloseDeadlines>,
}
impl Tree {
    /// Open a paged listing using an exact token from its parent listing.
    /// Each page is bounded by min(MaxTransactSize, 64 KiB), using the same
    /// parser, credit accounting and status handling as `list_directory_token`.
    pub async fn open_directory_reader_token(
        &self,
        connection: &mut Connection,
        token: &SmbPathToken,
    ) -> Result<DirectoryReader> {
        let file = self.open_directory_token(connection, token).await?;
        Ok(DirectoryReader {
            tree: self.clone(),
            connection: connection.clone(),
            token: token.clone(),
            file: Some(file),
            restart: true,
            buffer_len: Self::default_query_buffer_len(connection),
            finished: false,
            close_deadlines: None,
        })
    }
    /// Open a paged listing using a caller-supplied path. The path is encoded
    /// once; every returned entry carries its exact, fully bound reopen token.
    pub async fn open_directory_reader(
        &self,
        connection: &mut Connection,
        path: &str,
    ) -> Result<DirectoryReader> {
        self.open_directory_reader_token(connection, &self.path_token(path))
            .await
    }
}
impl DirectoryReader {
    /// Read one bounded server page. `None` means confirmed EOF and successful
    /// CLOSE. An empty successful page is not EOF and does not restart the scan.
    pub async fn next_page(&mut self) -> Result<Option<Vec<DirectoryEntry>>> {
        if self.finished {
            return Ok(None);
        }
        let file = self
            .file
            .ok_or_else(|| crate::Error::invalid_data("directory cursor is closed"))?;
        let result = self
            .tree
            .query_directory_step(&mut self.connection, file, self.restart, self.buffer_len)
            .await;
        self.restart = false;
        match result {
            Ok(QueryStepOutcome::Entries { mut entries, .. }) => {
                for entry in &mut entries {
                    entry.reopen_token = self.token.child(entry.reopen_token.units());
                }
                Ok(Some(entries))
            }
            Ok(QueryStepOutcome::NoMoreFiles { .. }) => {
                self.close_inner().await?;
                self.finished = true;
                Ok(None)
            }
            Err(primary) => {
                let _ = self.close_inner().await;
                self.finished = true;
                Err(primary)
            }
        }
    }
    /// Connection of this exact resolved tree, including cross-server DFS.
    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    /// Resolve reparse metadata on the same tree that supplied the entry.
    pub async fn reparse_descriptor(
        &self,
        entry: &DirectoryEntry,
    ) -> Result<super::ReparseDescriptor> {
        self.tree
            .reparse_descriptor_token(&self.connection, &entry.reopen_token, entry.is_directory)
            .await
    }

    /// Bound control-plane cleanup, including the automatic CLOSE on EOF.
    /// Deadlines do not change the enumeration/recovery timeout policy.
    pub fn set_close_deadlines(&mut self, deadlines: crate::CloseDeadlines) {
        self.close_deadlines = Some(deadlines);
    }

    async fn close_inner(&mut self) -> Result<()> {
        if let Some(file) = self.file.take() {
            match self.close_deadlines {
                Some(deadlines) => {
                    self.tree
                        .close_directory_bounded(&mut self.connection, file, deadlines)
                        .await?
                }
                None => self.tree.close_handle(&mut self.connection, file).await?,
            }
        }
        Ok(())
    }
    /// Release an unfinished enumeration. No further QUERY_DIRECTORY is sent.
    pub async fn close(mut self) -> Result<()> {
        self.close_inner().await
    }
}
impl Drop for DirectoryReader {
    fn drop(&mut self) {
        if self.file.is_some() {
            log::debug!("directory reader dropped before CLOSE; close early-stopped enumerations explicitly");
        }
    }
}
