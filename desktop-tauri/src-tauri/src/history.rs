use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

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
            params![to_sql_count(self.max_items)],
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
            .query_map(params![to_sql_count(limit), to_sql_count(offset)], |row| {
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
             WHERE content_type = 'text' AND CAST(data AS TEXT) LIKE ?1 ESCAPE '\\'
             ORDER BY created_at DESC LIMIT ?2",
        )?;

        // Escape LIKE wildcards (and the escape character itself) so they match literally
        let sanitized = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{sanitized}%");
        let entries = stmt
            .query_map(params![pattern, to_sql_count(limit)], |row| {
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

/// SQLite has no unsigned integer type; LIMIT/OFFSET parameters are bound as `i64`.
fn to_sql_count(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl HistoryRow {
    fn into_plain_entry(self) -> PlainEntry {
        let content_type = match self.content_type.as_str() {
            "image" => ContentType::Image,
            "file" => ContentType::File,
            _ => ContentType::Text,
        };
        let metadata: Metadata = serde_json::from_str(&self.metadata).unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn entry(id: &str, text: &str, secs: i64) -> PlainEntry {
        PlainEntry {
            id: id.to_string(),
            device_id: "dev-1".to_string(),
            device_name: "Laptop".to_string(),
            content_type: ContentType::Text,
            data: text.as_bytes().to_vec(),
            metadata: Metadata {
                size: text.len() as i64,
                ..Metadata::default()
            },
            created_at: Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap(),
        }
    }

    fn open(dir: &TempDir, max_items: usize) -> History {
        History::open(&dir.path().join("history.db"), max_items).unwrap()
    }

    #[test]
    fn open_creates_db_and_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("dir").join("history.db");
        let h = History::open(&path, 10).unwrap();
        assert!(path.is_file());
        assert!(h.list(10, 0).unwrap().is_empty());
    }

    #[test]
    fn add_and_list_newest_first() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        h.add(&entry("a", "first", 1)).unwrap();
        h.add(&entry("b", "second", 2)).unwrap();
        h.add(&entry("c", "third", 3)).unwrap();

        let ids: Vec<String> = h.list(10, 0).unwrap().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["c", "b", "a"]);
    }

    #[test]
    fn list_respects_limit_and_offset() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        for i in 0..5 {
            h.add(&entry(&format!("e{i}"), "x", i)).unwrap();
        }
        let page1: Vec<String> = h.list(2, 0).unwrap().into_iter().map(|e| e.id).collect();
        let page2: Vec<String> = h.list(2, 2).unwrap().into_iter().map(|e| e.id).collect();
        let page3: Vec<String> = h.list(2, 4).unwrap().into_iter().map(|e| e.id).collect();
        assert_eq!(page1, vec!["e4", "e3"]);
        assert_eq!(page2, vec!["e2", "e1"]);
        assert_eq!(page3, vec!["e0"]);
    }

    #[test]
    fn add_trims_to_max_items_keeping_newest() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 3);
        for i in 0..5 {
            h.add(&entry(&format!("e{i}"), "x", i)).unwrap();
        }
        let ids: Vec<String> = h.list(10, 0).unwrap().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["e4", "e3", "e2"]);
    }

    #[test]
    fn add_same_id_replaces_existing_row() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        h.add(&entry("dup", "v1", 1)).unwrap();
        h.add(&entry("dup", "v2", 2)).unwrap();
        let all = h.list(10, 0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].data, b"v2");
    }

    #[test]
    fn roundtrips_all_fields_and_metadata() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        let e = PlainEntry {
            id: "img-1".into(),
            device_id: "dev-9".into(),
            device_name: "Phone".into(),
            content_type: ContentType::Image,
            data: vec![0x89, 0x50, 0x4E, 0x47],
            metadata: Metadata {
                filename: Some("shot.png".into()),
                mime_type: Some("image/png".into()),
                size: 4,
                width: Some(640),
                height: Some(480),
            },
            created_at: Utc.timestamp_opt(1_700_000_123, 0).unwrap(),
        };
        h.add(&e).unwrap();

        let got = h.get("img-1").unwrap().expect("entry exists");
        assert_eq!(got.id, "img-1");
        assert_eq!(got.device_id, "dev-9");
        assert_eq!(got.device_name, "Phone");
        assert_eq!(got.content_type, ContentType::Image);
        assert_eq!(got.data, e.data);
        assert_eq!(got.metadata.filename.as_deref(), Some("shot.png"));
        assert_eq!(got.metadata.mime_type.as_deref(), Some("image/png"));
        assert_eq!(got.metadata.size, 4);
        assert_eq!(got.metadata.width, Some(640));
        assert_eq!(got.metadata.height, Some(480));
        assert_eq!(got.created_at, e.created_at);
    }

    #[test]
    fn file_content_type_roundtrips() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        let mut e = entry("f", "bytes", 1);
        e.content_type = ContentType::File;
        h.add(&e).unwrap();
        assert_eq!(h.get("f").unwrap().unwrap().content_type, ContentType::File);
    }

    #[test]
    fn get_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        assert!(h.get("nope").unwrap().is_none());
    }

    #[test]
    fn search_matches_text_entries_only() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        h.add(&entry("t1", "hello world", 1)).unwrap();
        h.add(&entry("t2", "goodbye world", 2)).unwrap();
        h.add(&entry("t3", "unrelated", 3)).unwrap();
        let mut img = entry("i1", "hello from an image blob", 4);
        img.content_type = ContentType::Image;
        h.add(&img).unwrap();

        let ids: Vec<String> = h
            .search("world", 10)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, vec!["t2", "t1"]);

        let ids: Vec<String> = h
            .search("hello", 10)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, vec!["t1"], "image entries must not match");

        assert!(h.search("zzz", 10).unwrap().is_empty());
        assert_eq!(h.search("world", 1).unwrap().len(), 1);
    }

    #[test]
    fn search_escapes_like_wildcards() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        h.add(&entry("pct", "100% done", 1)).unwrap();
        h.add(&entry("plain", "100 done", 2)).unwrap();
        h.add(&entry("under", "a_b", 3)).unwrap();
        h.add(&entry("nounder", "axb", 4)).unwrap();

        let ids: Vec<String> = h
            .search("%", 10)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, vec!["pct"], "% must be treated literally");

        let ids: Vec<String> = h
            .search("_", 10)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, vec!["under"], "_ must be treated literally");

        h.add(&entry("bs", "C:\\path", 5)).unwrap();
        let ids: Vec<String> = h
            .search("\\", 10)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, vec!["bs"], "backslash must be treated literally");
    }

    #[test]
    fn delete_and_clear() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        h.add(&entry("a", "x", 1)).unwrap();
        h.add(&entry("b", "y", 2)).unwrap();

        h.delete("a").unwrap();
        assert!(h.get("a").unwrap().is_none());
        assert!(h.get("b").unwrap().is_some());
        // Deleting a missing id is not an error
        h.delete("a").unwrap();

        h.clear().unwrap();
        assert!(h.list(10, 0).unwrap().is_empty());
    }

    #[test]
    fn corrupt_metadata_falls_back_to_default() {
        let dir = TempDir::new().unwrap();
        let h = open(&dir, 100);
        h.conn
            .execute(
                "INSERT INTO history (id, device_id, device_name, content_type, data, metadata, created_at)
                 VALUES ('bad', 'd', 'n', 'text', X'00', 'not json', 'not a date')",
                [],
            )
            .unwrap();
        let got = h.get("bad").unwrap().unwrap();
        assert_eq!(got.metadata.size, 0);
        assert!(got.metadata.filename.is_none());
        // Unparseable timestamps are replaced with "now" rather than failing
        assert!(got.created_at <= Utc::now());
    }

    #[test]
    fn to_sql_count_saturates() {
        assert_eq!(to_sql_count(0), 0);
        assert_eq!(to_sql_count(42), 42);
        assert_eq!(to_sql_count(usize::MAX), i64::MAX);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("history.db");
        {
            let h = History::open(&path, 100).unwrap();
            h.add(&entry("a", "persist me", 1)).unwrap();
        }
        let h = History::open(&path, 100).unwrap();
        assert_eq!(h.get("a").unwrap().unwrap().data, b"persist me");
    }
}
