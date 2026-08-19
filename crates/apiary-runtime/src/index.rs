//! The semantic index — SPEC §9 store 2. Derived, rebuildable, local.
//!
//! The episodic log is the ground truth; the index is a lens over it. It is
//! maintained incrementally (new log entries embedded on each run), stored
//! next to the log, and safe to delete — a rebuild costs only embedding
//! calls. Retrieval merges into the working set alongside the recency tail,
//! so an agent remembers what is RELEVANT, not just what is recent.
//!
//! Embedders bind from the manifest's `embed` inference slot:
//! - `ollama`: real embeddings from a local model (nothing leaves the host)
//! - `hash`: deterministic character-trigram hashing — a degenerate,
//!   model-free embedder. Honest about what it is: lexical similarity, not
//!   semantics. Default for tests and hosts without a model; swap the slot
//!   provider to upgrade.

use apiary_core::log::{EntryBody, EpisodicLog};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub trait Embedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, crate::Error>;
    /// Identity string stored with vectors — a changed embedder invalidates
    /// the index (dimensions and spaces don't mix); detected, not assumed.
    fn id(&self) -> String;
}

/// Deterministic character-trigram hashing into a fixed-dim vector.
pub struct HashEmbedder;

impl Embedder for HashEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, crate::Error> {
        const DIM: usize = 256;
        let mut v = vec![0f32; DIM];
        let lower = text.to_lowercase();
        let bytes: Vec<char> = lower.chars().collect();
        for w in bytes.windows(3) {
            let mut h: u64 = 1469598103934665603;
            for c in w {
                h ^= *c as u64;
                h = h.wrapping_mul(1099511628211);
            }
            v[(h % DIM as u64) as usize] += 1.0;
        }
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            v.iter_mut().for_each(|x| *x /= norm);
        }
        Ok(v)
    }
    fn id(&self) -> String {
        "hash:trigram-256".into()
    }
}

/// Local Ollama embeddings — the "sensitive data never leaves the host"
/// embedder.
pub struct OllamaEmbedder {
    pub base_url: String,
    pub model: String,
}

impl Embedder for OllamaEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, crate::Error> {
        let client = reqwest::blocking::Client::new();
        let resp: serde_json::Value = client
            .post(format!("{}/api/embeddings", self.base_url))
            .json(&serde_json::json!({"model": self.model, "prompt": text}))
            .send()
            .map_err(|e| crate::Error::Provider(format!("ollama embed: {e}")))?
            .json()
            .map_err(|e| crate::Error::Provider(format!("ollama embed parse: {e}")))?;
        let v = resp["embedding"]
            .as_array()
            .ok_or_else(|| {
                crate::Error::Provider(format!(
                    "ollama embed: no embedding in response ({})",
                    resp["error"].as_str().unwrap_or("is the model pulled?")
                ))
            })?
            .iter()
            .filter_map(|x| x.as_f64().map(|f| f as f32))
            .collect();
        Ok(v)
    }
    fn id(&self) -> String {
        format!("ollama:{}", self.model)
    }
}

/// Bind an embedder from the manifest's `embed` slot, if declared.
pub fn bind_embedder(manifest: &apiary_core::manifest::Manifest) -> Option<Box<dyn Embedder>> {
    let slot = manifest.inference.iter().find(|s| s.name == "embed")?;
    match slot.provider.as_str() {
        "ollama" => Some(Box::new(OllamaEmbedder {
            base_url: "http://localhost:11434".into(),
            model: slot
                .model
                .clone()
                .unwrap_or_else(|| "nomic-embed-text".into()),
        })),
        "hash" | "mock" => Some(Box::new(HashEmbedder)),
        _ => None,
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct IndexRow {
    event_id: String,
    embedder: String,
    text: String,
    vector: Vec<f32>,
}

pub struct SemanticIndex {
    path: PathBuf,
}

/// What one entry looks like to retrieval.
pub struct Hit {
    pub event_id: String,
    pub text: String,
    pub score: f32,
}

fn entry_text(body: &EntryBody) -> String {
    body.index_text()
}

impl SemanticIndex {
    pub fn open(agent_dir: &Path) -> Self {
        Self {
            path: agent_dir.join("index.jsonl"),
        }
    }

    fn rows(&self) -> Result<Vec<IndexRow>, crate::Error> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for line in std::fs::read_to_string(&self.path)?.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line)?);
        }
        Ok(out)
    }

    /// Embed any log entries not yet in the index. A changed embedder id
    /// discards and rebuilds — derived state is disposable by design.
    pub fn update(
        &self,
        log: &EpisodicLog,
        embedder: &dyn Embedder,
    ) -> Result<usize, crate::Error> {
        let mut rows = self.rows()?;
        if rows.iter().any(|r| r.embedder != embedder.id()) {
            rows.clear();
            let _ = std::fs::remove_file(&self.path);
        }
        let known: BTreeSet<String> = rows.iter().map(|r| r.event_id.clone()).collect();
        let mut added = 0;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path)?;
        for event in log.read_all()? {
            let id = event.id.to_hex();
            if known.contains(&id) {
                continue;
            }
            let Ok(body) = EpisodicLog::parse_body(&event) else {
                continue;
            };
            let text = entry_text(&body);
            let row = IndexRow {
                event_id: id,
                embedder: embedder.id(),
                vector: embedder.embed(&text)?,
                text,
            };
            writeln!(file, "{}", serde_json::to_string(&row)?)?;
            added += 1;
        }
        Ok(added)
    }

    /// Top-k by cosine similarity, excluding the given event ids (typically
    /// the recency tail — retrieval adds what recency missed).
    pub fn query(
        &self,
        embedder: &dyn Embedder,
        text: &str,
        k: usize,
        exclude: &BTreeSet<String>,
    ) -> Result<Vec<Hit>, crate::Error> {
        let q = embedder.embed(text)?;
        let mut hits: Vec<Hit> = self
            .rows()?
            .into_iter()
            .filter(|r| r.embedder == embedder.id() && !exclude.contains(&r.event_id))
            .map(|r| {
                let score = r.vector.iter().zip(&q).map(|(a, b)| a * b).sum::<f32>();
                Hit {
                    event_id: r.event_id,
                    text: r.text,
                    score,
                }
            })
            .collect();
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(k);
        hits.retain(|h| h.score > 0.0);
        Ok(hits)
    }

    /// Refresh log/vault-derived rows and query one in-memory snapshot. The
    /// older update → vault update → query sequence parsed the growing JSONL
    /// index three times before every model call. Derived memory is an
    /// off-chain read model; one snapshot and one persistence pass is enough.
    pub fn refresh_and_query(
        &self,
        log: &EpisodicLog,
        vaults: &[apiary_core::manifest::VaultRef],
        embedder: &dyn Embedder,
        text: &str,
        k: usize,
        exclude: &BTreeSet<String>,
    ) -> Result<Vec<Hit>, crate::Error> {
        let embedder_id = embedder.id();
        let mut rows = self.rows()?;
        let mut rewrite = false;
        if rows.iter().any(|row| row.embedder != embedder_id) {
            rows.clear();
            rewrite = true;
        }

        let mut known = rows
            .iter()
            .map(|row| row.event_id.clone())
            .collect::<BTreeSet<_>>();
        let mut appended = Vec::new();
        for event in log.read_all()? {
            let id = event.id.to_hex();
            if known.contains(&id) {
                continue;
            }
            let Ok(body) = EpisodicLog::parse_body(&event) else {
                continue;
            };
            let row_text = entry_text(&body);
            let row = IndexRow {
                event_id: id.clone(),
                embedder: embedder_id.clone(),
                vector: embedder.embed(&row_text)?,
                text: row_text,
            };
            known.insert(id);
            appended.push(row.clone());
            rows.push(row);
        }

        // Vault rows are replaceable projections. This deliberately includes
        // the empty-vault case so removing a grant removes its recalled data.
        let mut desired = Vec::new();
        for vault in vaults {
            let Ok(root) = crate::vault::open_root(&vault.path) else {
                continue;
            };
            for note in crate::vault::walk(&root)? {
                let Ok(content) = crate::vault::read_note(&root, &note.rel) else {
                    continue;
                };
                let fingerprint = crate::vault::fingerprint(&content);
                for (index, chunk) in crate::vault::chunks(&content, 1200).into_iter().enumerate() {
                    desired.push((
                        format!("vault:{}/{}#{index}:{fingerprint}", vault.name, note.rel),
                        format!("[{} note {}] {}", vault.name, note.rel, chunk),
                    ));
                }
            }
        }
        let desired_ids = desired
            .iter()
            .map(|(id, _)| id.as_str())
            .collect::<BTreeSet<_>>();
        let before = rows.len();
        rows.retain(|row| {
            !row.event_id.starts_with("vault:") || desired_ids.contains(row.event_id.as_str())
        });
        if rows.len() != before {
            rewrite = true;
        }
        known = rows
            .iter()
            .map(|row| row.event_id.clone())
            .collect::<BTreeSet<_>>();
        for (id, row_text) in desired {
            if known.contains(&id) {
                continue;
            }
            rows.push(IndexRow {
                event_id: id.clone(),
                embedder: embedder_id.clone(),
                vector: embedder.embed(&row_text)?,
                text: row_text,
            });
            known.insert(id);
            rewrite = true;
        }

        if rewrite {
            let mut output = String::new();
            for row in &rows {
                output.push_str(&serde_json::to_string(row)?);
                output.push('\n');
            }
            std::fs::write(&self.path, output)?;
        } else if !appended.is_empty() {
            let mut options = std::fs::OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&self.path)?;
            for row in appended {
                writeln!(file, "{}", serde_json::to_string(&row)?)?;
            }
        }
        #[cfg(unix)]
        if self.path.exists() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }

        let query = embedder.embed(text)?;
        let mut hits = rows
            .into_iter()
            .filter(|row| row.embedder == embedder_id && !exclude.contains(&row.event_id))
            .map(|row| Hit {
                event_id: row.event_id,
                text: row.text,
                score: row
                    .vector
                    .iter()
                    .zip(&query)
                    .map(|(left, right)| left * right)
                    .sum(),
            })
            .filter(|hit| hit.score > 0.0)
            .collect::<Vec<_>>();
        hits.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(k);
        Ok(hits)
    }
}

impl SemanticIndex {
    /// Embed the manifest's vaults into the index: heading-aware chunks,
    /// staleness-tracked by a content fingerprint in the row id
    /// (`vault:<name>/<rel>#<n>:<fp>`). Changed or deleted notes get their
    /// stale rows dropped; the whole vault side rebuilds cheaply because
    /// derived state is disposable by design.
    pub fn update_vaults(
        &self,
        vaults: &[apiary_core::manifest::VaultRef],
        embedder: &dyn Embedder,
    ) -> Result<usize, crate::Error> {
        if vaults.is_empty() {
            return Ok(0);
        }
        let mut rows = self.rows()?;
        if rows.iter().any(|r| r.embedder != embedder.id()) {
            rows.clear();
            let _ = std::fs::remove_file(&self.path);
        }
        // Desired vault rows.
        let mut desired: Vec<(String, String)> = Vec::new(); // (id, text)
        for v in vaults {
            let root = match crate::vault::open_root(&v.path) {
                Ok(r) => r,
                Err(_) => continue, // unreachable vault: keep the index's old view? No — drop below.
            };
            for note in crate::vault::walk(&root)? {
                let Ok(content) = crate::vault::read_note(&root, &note.rel) else {
                    continue;
                };
                let fp = crate::vault::fingerprint(&content);
                for (i, chunk) in crate::vault::chunks(&content, 1200).into_iter().enumerate() {
                    desired.push((
                        format!("vault:{}/{}#{i}:{fp}", v.name, note.rel),
                        format!("[{} note {}] {}", v.name, note.rel, chunk),
                    ));
                }
            }
        }
        let desired_ids: BTreeSet<&String> = desired.iter().map(|(id, _)| id).collect();
        // Drop stale vault rows (changed fingerprint, deleted note, or a
        // vault removed from the manifest).
        let before = rows.len();
        rows.retain(|r| !r.event_id.starts_with("vault:") || desired_ids.contains(&r.event_id));
        let dropped = before - rows.len();
        let known: BTreeSet<String> = rows.iter().map(|r| r.event_id.clone()).collect();
        let mut added = 0;
        for (id, text) in desired {
            if known.contains(&id) {
                continue;
            }
            rows.push(IndexRow {
                event_id: id,
                embedder: embedder.id(),
                vector: embedder.embed(&text)?,
                text,
            });
            added += 1;
        }
        if dropped > 0 || added > 0 {
            let mut out = String::new();
            for r in &rows {
                out.push_str(&serde_json::to_string(r)?);
                out.push('\n');
            }
            std::fs::write(&self.path, out)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiary_core::custody::Custody;
    use apiary_core::log::Tier;
    use nostr::prelude::*;

    #[test]
    fn hash_embedder_ranks_similar_text_higher() {
        let e = HashEmbedder;
        let a = e.embed("publish a note about bees and honey").unwrap();
        let b = e.embed("publish a note about bees").unwrap();
        let c = e.embed("rotate the database credentials").unwrap();
        let dot = |x: &[f32], y: &[f32]| x.iter().zip(y).map(|(p, q)| p * q).sum::<f32>();
        assert!(dot(&a, &b) > dot(&a, &c));
    }

    #[test]
    fn index_updates_incrementally_and_retrieves_relevant() {
        let dir = std::env::temp_dir().join(format!("apiary-idx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut custody = Custody::new();
        let h = custody.admit(Keys::generate());
        let log = EpisodicLog::open(&dir);
        let mk = |task: &str| apiary_core::log::EntryBody {
            action: "run.task".into(),
            model: None,
            cost: None,
            harness: None,
            outcome: "ok".into(),
            detail: Some(serde_json::json!({ "task": task })),
        };
        log.append(&custody, &h, Tier::Self_, &mk("publish a note about bees"))
            .unwrap();
        log.append(
            &custody,
            &h,
            Tier::Self_,
            &mk("rotate the database credentials"),
        )
        .unwrap();

        let idx = SemanticIndex::open(&dir);
        let e = HashEmbedder;
        assert_eq!(idx.update(&log, &e).unwrap(), 2);
        assert_eq!(idx.update(&log, &e).unwrap(), 0); // incremental: nothing new

        let hits = idx
            .query(&e, "tell me about bees and honey", 1, &BTreeSet::new())
            .unwrap();
        assert!(hits[0].text.contains("bees"), "{}", hits[0].text);
        let combined = idx
            .refresh_and_query(
                &log,
                &[],
                &e,
                "tell me about bees and honey",
                1,
                &BTreeSet::new(),
            )
            .unwrap();
        assert!(combined[0].text.contains("bees"), "{}", combined[0].text);
        std::fs::remove_dir_all(&dir).ok();
    }
}
