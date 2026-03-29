use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use std::path::Path;
use thiserror::Error;

use crate::proto::models::{ContentType, Metadata, PlainEntry};

#[derive(Error, Debug)]
pub enum HistoryError {
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Local clipboard history stored in SQLite.
pub struct History {
    conn: Connection,
    max_items: usize,
}

impl History {
    pub fn open(db_path: &Path, max_items: usize) -> Result<Self, HistoryError> {
        if let Some(dir) = db_path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let conn = Connection::open(db_path)?;
        migrate(&conn)?;
        Ok(History { conn, max_items })
    }

    /// Adds a decrypted entry to local history.
    pub fn add(&self, entry: &PlainEntry) -> Result<(), HistoryError> {
        let meta_json = serde_json::to_string(&entry.metadata)?;
        let ct = entry.content_type.to_string();

        self.conn.execute(
            "INSERT OR REPLACE INTO history (id, device_id, device_name, content_type, data, metadata, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.id,
                entry.device_id,
                entry.device_name,
                ct,
                entry.data,
                meta_json,
                entry.created_at.to_rfc3339(),
            ],
        )?;

        // Trim excess entries
        self.conn.execute(
            "DELETE FROM history WHERE id NOT IN (
                SELECT id FROM history ORDER BY created_at DESC LIMIT ?1
            )",
            params![self.max_items],
        )?;

        Ok(())
    }

    /// Returns recent clipboard history entries.
    pub fn list(&self, limit: usize, offset: usize) -> Result<Vec<PlainEntry>, HistoryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_id, device_name, content_type, data, metadata, created_at
             FROM history ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
        )?;

        let entries = stmt
            .query_map(params![limit, offset], |row| {
                Ok(HistoryRow {
                    id: row.get(0)?,
                    device_id: row.get(1)?,
                    device_name: row.get(2)?,
                    content_type: row.get(3)?,
                    data: row.get(4)?,
                    metadata: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .map(|r| r.into_plain_entry())
            .collect();

        Ok(entries)
    }

    /// Searches history by text content.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<PlainEntry>, HistoryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_id, device_name, content_type, data, metadata, created_at
             FROM history
             WHERE content_type = 'text' AND CAST(data AS TEXT) LIKE ?1
             ORDER BY created_at DESC LIMIT ?2",
        )?;

        let sanitized = query.replace('%', "\\%").replace('_', "\\_");
        let pattern = format!("%{sanitized}%");
        let entries = stmt
            .query_map(params![pattern, limit], |row| {
                Ok(HistoryRow {
                    id: row.get(0)?,
                    device_id: row.get(1)?,
                    device_name: row.get(2)?,
                    content_type: row.get(3)?,
                    data: row.get(4)?,
                    metadata: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .map(|r| r.into_plain_entry())
            .collect();

        Ok(entries)
    }

    /// Gets a specific entry by ID.
    pub fn get(&self, id: &str) -> Result<Option<PlainEntry>, HistoryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_id, device_name, content_type, data, metadata, created_at
             FROM history WHERE id = ?1",
        )?;

        let result = stmt
            .query_map(params![id], |row| {
                Ok(HistoryRow {
                    id: row.get(0)?,
                    device_id: row.get(1)?,
                    device_name: row.get(2)?,
                    content_type: row.get(3)?,
                    data: row.get(4)?,
                    metadata: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .next()
            .map(|r| r.into_plain_entry());

        Ok(result)
    }

    /// Deletes a single entry by ID.
    pub fn delete(&self, id: &str) -> Result<(), HistoryError> {
        self.conn
            .execute("DELETE FROM history WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Clears all history.
    pub fn clear(&self) -> Result<(), HistoryError> {
        self.conn.execute("DELETE FROM history", [])?;
        Ok(())
    }
}

struct HistoryRow {
    id: String,
    device_id: String,
    device_name: String,
    content_type: String,
    data: Vec<u8>,
    metadata: String,
    created_at: String,
}

impl HistoryRow {
    fn into_plain_entry(self) -> PlainEntry {
        let content_type = match self.content_type.as_str() {
            "image" => ContentType::Image,
            "file" => ContentType::File,
            _ => ContentType::Text,
        };
        let metadata: Metadata =
            serde_json::from_str(&self.metadata).unwrap_or_default();
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        PlainEntry {
            id: self.id,
            device_id: self.device_id,
            device_name: self.device_name,
            content_type,
            data: self.data,
            metadata,
            created_at,
        }
    }
}

fn migrate(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS history (
            id          TEXT PRIMARY KEY,
            device_id   TEXT NOT NULL,
            device_name TEXT NOT NULL,
            content_type TEXT NOT NULL,
            data        BLOB NOT NULL,
            metadata    TEXT,
            created_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_history_created ON history(created_at DESC);",
    )?;
    Ok(())
}
