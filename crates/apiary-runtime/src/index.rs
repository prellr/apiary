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
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

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
    timeout: Duration,
}

impl Embedder for OllamaEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, crate::Error> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(75))
            .timeout(self.timeout)
            .build()
            .map_err(|e| crate::Error::Provider(format!("ollama embed client: {e}")))?;
        let resp: serde_json::Value = client
            .post(format!("{}/api/embeddings", self.base_url))
            .json(&serde_json::json!({
                "model": self.model,
                "prompt": text,
                "keep_alive": "30m",
            }))
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
        mark_embedder_warm(&self.id());
        Ok(v)
    }
    fn id(&self) -> String {
        format!("ollama:{}", self.model)
    }
}

const DEEP_RECALL_TIMEOUT: Duration = Duration::from_millis(250);
const BACKGROUND_EMBED_TIMEOUT: Duration = Duration::from_secs(10);
const EMBEDDER_WARM_TTL: Duration = Duration::from_secs(5 * 60);

fn warm_embedders() -> &'static Mutex<HashMap<String, Instant>> {
    static WARM: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    WARM.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mark_embedder_warm(id: &str) {
    warm_embedders()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(id.to_string(), Instant::now());
}

fn clear_embedder_warm(id: &str) {
    warm_embedders()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(id);
}

fn embedder_is_warm(id: &str) -> bool {
    let mut warm = warm_embedders()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    warm.retain(|_, warmed_at| warmed_at.elapsed() < EMBEDDER_WARM_TTL);
    warm.contains_key(id)
}

fn ollama_embedder(
    slot: &apiary_core::manifest::InferenceSlot,
    timeout: Duration,
) -> Box<dyn Embedder> {
    Box::new(OllamaEmbedder {
        base_url: "http://localhost:11434".into(),
        model: slot
            .model
            .clone()
            .unwrap_or_else(|| "nomic-embed-text".into()),
        timeout,
    })
}

/// Bind an embedder from the manifest's `embed` slot, if declared.
pub fn bind_embedder(manifest: &apiary_core::manifest::Manifest) -> Option<Box<dyn Embedder>> {
    let slot = manifest.inference.iter().find(|s| s.name == "embed")?;
    match slot.provider.as_str() {
        "ollama" => Some(ollama_embedder(slot, DEEP_RECALL_TIMEOUT)),
        "hash" | "mock" => Some(Box::new(HashEmbedder)),
        _ => None,
    }
}

fn bind_background_embedder(
    manifest: &apiary_core::manifest::Manifest,
) -> Option<Box<dyn Embedder>> {
    let slot = manifest
        .inference
        .iter()
        .find(|slot| slot.name == "embed")?;
    match slot.provider.as_str() {
        "ollama" => Some(ollama_embedder(slot, BACKGROUND_EMBED_TIMEOUT)),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiskStamp {
    len: u64,
    modified_ns: u128,
}

#[derive(Default)]
struct MemorySnapshot {
    loaded: bool,
    stamp: Option<DiskStamp>,
    rows: Vec<IndexRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PathStamp {
    kind: String,
    rel: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultWatch {
    name: String,
    configured_path: String,
    canonical_root: String,
    paths: Vec<PathStamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultProjection {
    version: u8,
    configuration: String,
    watches: Vec<VaultWatch>,
}

const VAULT_PROJECTION_VERSION: u8 = 1;

type SharedSnapshot = Arc<Mutex<MemorySnapshot>>;

fn snapshots() -> &'static Mutex<HashMap<PathBuf, SharedSnapshot>> {
    static SNAPSHOTS: OnceLock<Mutex<HashMap<PathBuf, SharedSnapshot>>> = OnceLock::new();
    SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn refreshes() -> &'static Mutex<HashSet<PathBuf>> {
    static REFRESHES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    REFRESHES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn disk_stamp(path: &Path) -> Option<DiskStamp> {
    let metadata = path.metadata().ok()?;
    let modified_ns = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(DiskStamp {
        len: metadata.len(),
        modified_ns,
    })
}

fn metadata_signature(path: &Path) -> Result<String, crate::Error> {
    let metadata = path
        .metadata()
        .map_err(|e| crate::Error::Provider(format!("memory metadata {}: {e}", path.display())))?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(format!(
            "{}:{modified}:{}:{}",
            metadata.len(),
            metadata.ctime(),
            metadata.ctime_nsec()
        ))
    }
    #[cfg(not(unix))]
    Ok(format!("{}:{modified}", metadata.len()))
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

fn vault_configuration(vaults: &[apiary_core::manifest::VaultRef]) -> String {
    serde_json::to_string(
        &vaults
            .iter()
            .map(|vault| {
                serde_json::json!({
                    "name": vault.name,
                    "path": vault.path,
                    "kind": vault.kind,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default()
}

fn vault_projection_is_current(
    projection: &VaultProjection,
    vaults: &[apiary_core::manifest::VaultRef],
) -> bool {
    if projection.version != VAULT_PROJECTION_VERSION
        || projection.configuration != vault_configuration(vaults)
        || projection.watches.len() != vaults.len()
    {
        return false;
    }
    projection.watches.iter().all(|watch| {
        let Ok(root) = crate::vault::open_root(&watch.configured_path) else {
            return false;
        };
        if root.to_string_lossy() != watch.canonical_root {
            return false;
        }
        watch.paths.iter().all(|stamp| {
            let path = if stamp.rel.is_empty() {
                root.clone()
            } else {
                root.join(&stamp.rel)
            };
            metadata_signature(&path).is_ok_and(|value| value == stamp.signature)
        })
    })
}

fn scan_vault_rows(
    vaults: &[apiary_core::manifest::VaultRef],
) -> Result<(Vec<(String, String)>, VaultProjection), crate::Error> {
    let mut desired = Vec::new();
    let mut watches = Vec::new();
    for vault in vaults {
        let root = match crate::vault::open_root(&vault.path) {
            Ok(root) => root,
            Err(_) => continue,
        };
        let inventory = crate::vault::inventory(&root)?;
        let mut paths = Vec::new();
        for relative in &inventory.directories {
            let path = if relative.is_empty() {
                root.clone()
            } else {
                root.join(relative)
            };
            paths.push(PathStamp {
                kind: "directory".into(),
                rel: relative.clone(),
                signature: metadata_signature(&path)?,
            });
        }
        for note in &inventory.notes {
            let path = root.join(&note.rel);
            paths.push(PathStamp {
                kind: "note".into(),
                rel: note.rel.clone(),
                signature: metadata_signature(&path)?,
            });
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
        paths.sort_by(|left, right| (&left.kind, &left.rel).cmp(&(&right.kind, &right.rel)));
        watches.push(VaultWatch {
            name: vault.name.clone(),
            configured_path: vault.path.clone(),
            canonical_root: root.to_string_lossy().into_owned(),
            paths,
        });
    }
    Ok((
        desired,
        VaultProjection {
            version: VAULT_PROJECTION_VERSION,
            configuration: vault_configuration(vaults),
            watches,
        },
    ))
}

impl SemanticIndex {
    pub fn open(agent_dir: &Path) -> Self {
        Self {
            path: agent_dir.join("index.jsonl"),
        }
    }

    fn snapshot(&self) -> SharedSnapshot {
        let mut snapshots = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        snapshots
            .entry(self.path.clone())
            .or_insert_with(|| Arc::new(Mutex::new(MemorySnapshot::default())))
            .clone()
    }

    fn read_rows_from_disk(&self) -> Result<Vec<IndexRow>, crate::Error> {
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

    fn rows(&self) -> Result<Vec<IndexRow>, crate::Error> {
        let stamp = disk_stamp(&self.path);
        let snapshot = self.snapshot();
        let mut cached = snapshot.lock().unwrap_or_else(|e| e.into_inner());
        if cached.loaded && cached.stamp == stamp {
            return Ok(cached.rows.clone());
        }
        let rows = self.read_rows_from_disk()?;
        cached.loaded = true;
        cached.stamp = stamp;
        cached.rows = rows.clone();
        Ok(rows)
    }

    fn store_rows(&self, rows: &[IndexRow]) -> Result<(), crate::Error> {
        let temporary = self
            .path
            .with_extension(format!("jsonl.tmp.{}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        for row in rows {
            writeln!(file, "{}", serde_json::to_string(row)?)?;
        }
        file.flush()?;
        std::fs::rename(&temporary, &self.path)?;
        let snapshot = self.snapshot();
        let mut cached = snapshot.lock().unwrap_or_else(|e| e.into_inner());
        cached.loaded = true;
        cached.stamp = disk_stamp(&self.path);
        cached.rows = rows.to_vec();
        Ok(())
    }

    fn vault_projection_path(&self) -> PathBuf {
        self.path.with_file_name("index.vaults.json")
    }

    fn read_vault_projection(&self) -> Option<VaultProjection> {
        let raw = std::fs::read_to_string(self.vault_projection_path()).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn write_vault_projection(&self, projection: &VaultProjection) -> Result<(), crate::Error> {
        let path = self.vault_projection_path();
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        serde_json::to_writer(&mut file, projection)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    /// Embed any log entries not yet in the index. A changed embedder id
    /// discards and rebuilds — derived state is disposable by design.
    pub fn update(
        &self,
        log: &EpisodicLog,
        embedder: &dyn Embedder,
    ) -> Result<usize, crate::Error> {
        let mut rows = self.rows()?;
        let embedder_id = embedder.id();
        let mut rewrite = false;
        if rows.iter().any(|r| r.embedder != embedder_id) {
            rows.clear();
            rewrite = true;
        }
        let mut known: BTreeSet<String> = rows.iter().map(|r| r.event_id.clone()).collect();
        let mut added = 0;
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
                event_id: id.clone(),
                embedder: embedder_id.clone(),
                vector: embedder.embed(&text)?,
                text,
            };
            known.insert(id);
            rows.push(row);
            added += 1;
        }
        if rewrite || added > 0 {
            self.store_rows(&rows)?;
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
        let embedder_id = embedder.id();
        if embedder_id.starts_with("ollama:") && !embedder_is_warm(&embedder_id) {
            return Err(crate::Error::Provider(
                "semantic memory is warming in the background".into(),
            ));
        }
        let q = match embedder.embed(text) {
            Ok(vector) => vector,
            Err(error) => {
                if embedder_id.starts_with("ollama:") {
                    clear_embedder_warm(&embedder_id);
                }
                return Err(error);
            }
        };
        let mut hits: Vec<Hit> = self
            .rows()?
            .into_iter()
            .filter(|r| r.embedder == embedder_id && !exclude.contains(&r.event_id))
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

    /// Always-available local recall that does not wake an inference service.
    /// This is intentionally lexical rather than pretending to be semantic:
    /// it keeps names, projects, and repeated topics available on every turn
    /// in a few milliseconds. Explicit memory-oriented requests additionally
    /// use `query` for deep semantic recall.
    pub fn query_lexical(
        &self,
        text: &str,
        k: usize,
        exclude: &BTreeSet<String>,
    ) -> Result<Vec<Hit>, crate::Error> {
        let lexical = HashEmbedder;
        let query = lexical.embed(text)?;
        let mut hits = self
            .rows()?
            .into_iter()
            .filter(|row| !exclude.contains(&row.event_id))
            .filter_map(|row| {
                let vector = lexical.embed(&row.text).ok()?;
                let score = vector
                    .iter()
                    .zip(&query)
                    .map(|(left, right)| left * right)
                    .sum::<f32>();
                (score > 0.0).then_some(Hit {
                    event_id: row.event_id,
                    text: row.text,
                    score,
                })
            })
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

    /// Refresh the rebuildable deep-memory projection. Callers should run this
    /// off the response path; queries continue using the previous immutable
    /// in-memory snapshot until the replacement is complete.
    pub fn refresh(
        &self,
        log: &EpisodicLog,
        vaults: &[apiary_core::manifest::VaultRef],
        embedder: &dyn Embedder,
    ) -> Result<usize, crate::Error> {
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
        let indexed_log_entries = rows
            .iter()
            .filter(|row| !row.event_id.starts_with("vault:"))
            .count();
        let indexed_log_tip = rows
            .iter()
            .rev()
            .find(|row| !row.event_id.starts_with("vault:"))
            .map(|row| row.event_id.clone());
        let log_summary = log.derived_summary()?;
        let mut new_events = Vec::new();
        let incremental = if !rewrite && log_summary.entry_count >= indexed_log_entries {
            let delta = log_summary.entry_count - indexed_log_entries;
            if delta == 0 {
                log_summary.tip == indexed_log_tip
            } else {
                let tail = log.tail(delta)?;
                let first_prev = tail.first().and_then(|event| {
                    event.tags.iter().find_map(|tag| {
                        let values = tag.as_slice();
                        (values.first().map(String::as_str) == Some("prev"))
                            .then(|| values.get(1).cloned())?
                    })
                });
                let last = tail.last().map(|event| event.id.to_hex());
                let continues = indexed_log_entries == 0
                    || first_prev.is_none() // externally signed anchor
                    || first_prev == indexed_log_tip;
                if tail.len() == delta && continues && last == log_summary.tip {
                    new_events = tail;
                    true
                } else {
                    false
                }
            }
        } else {
            false
        };
        if !incremental {
            // A truncation/import/replacement drops only rows no longer in
            // signed history. Surviving vectors remain valid, avoiding a
            // full re-embed after recovery or compaction.
            let events = log.read_all()?;
            let current = events
                .iter()
                .map(|event| event.id.to_hex())
                .collect::<BTreeSet<_>>();
            let before = rows.len();
            rows.retain(|row| {
                row.event_id.starts_with("vault:") || current.contains(&row.event_id)
            });
            rewrite |= rows.len() != before;
            known = rows
                .iter()
                .map(|row| row.event_id.clone())
                .collect::<BTreeSet<_>>();
            new_events = events;
        }
        for event in new_events {
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

        // File discovery and content reads happen only when the persisted
        // stat projection says a vault changed. This work is background-only.
        let current_projection = self.read_vault_projection();
        let vaults_current = !rewrite
            && current_projection
                .as_ref()
                .is_some_and(|projection| vault_projection_is_current(projection, vaults));
        let mut refreshed_projection = None;
        if !vaults_current {
            let (desired, projection) = scan_vault_rows(vaults)?;
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
            refreshed_projection = Some(projection);
        }

        let added = appended.len();
        if rewrite || !appended.is_empty() {
            self.store_rows(&rows)?;
        }
        if let Some(projection) = refreshed_projection {
            self.write_vault_projection(&projection)?;
        }
        Ok(added)
    }

    /// Compatibility helper for explicit callers that intentionally require a
    /// fresh projection. Interactive/voice runs use `query` directly.
    pub fn refresh_and_query(
        &self,
        log: &EpisodicLog,
        vaults: &[apiary_core::manifest::VaultRef],
        embedder: &dyn Embedder,
        text: &str,
        k: usize,
        exclude: &BTreeSet<String>,
    ) -> Result<Vec<Hit>, crate::Error> {
        self.refresh(log, vaults, embedder)?;
        self.query(embedder, text, k, exclude)
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
        let mut rows = self.rows()?;
        let embedder_id = embedder.id();
        if rows.iter().any(|r| r.embedder != embedder_id) {
            rows.clear();
        }
        let (desired, projection) = scan_vault_rows(vaults)?;
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
                embedder: embedder_id.clone(),
                vector: embedder.embed(&text)?,
                text,
            });
            added += 1;
        }
        if dropped > 0 || added > 0 {
            self.store_rows(&rows)?;
        }
        self.write_vault_projection(&projection)?;
        Ok(added)
    }
}

/// Memory vaults come from explicit ambient-memory declarations plus granted
/// Markdown/Obsidian connectors. A connector grant is the act that makes that
/// local knowledge available; duplicate names resolve to the explicit entry.
pub fn configured_vaults(
    manifest: &apiary_core::manifest::Manifest,
) -> Vec<apiary_core::manifest::VaultRef> {
    let mut vaults = manifest.memory.vaults.clone();
    for connector in manifest
        .connectors
        .iter()
        .filter(|connector| connector.kind == "obsidian" || connector.kind == "markdown-vault")
    {
        if let Some(values) = connector
            .caps
            .get("vaults")
            .and_then(|value| value.as_array())
        {
            for value in values {
                if let (Some(name), Some(path)) = (value["name"].as_str(), value["path"].as_str()) {
                    if !vaults.iter().any(|vault| vault.name == name) {
                        vaults.push(apiary_core::manifest::VaultRef {
                            name: name.to_string(),
                            path: path.to_string(),
                            kind: Some(
                                if connector.kind == "obsidian" {
                                    "obsidian"
                                } else {
                                    "markdown"
                                }
                                .into(),
                            ),
                        });
                    }
                }
            }
        }
    }
    vaults
}

/// Schedule deep-memory maintenance without putting discovery, file reads, or
/// embedding on the interactive path. At most one refresh runs per agent;
/// queries keep using the prior immutable snapshot while it is rebuilt.
pub fn schedule_refresh(manifest: apiary_core::manifest::Manifest, agent_dir: PathBuf) -> bool {
    if bind_background_embedder(&manifest).is_none() {
        return false;
    }
    let index_path = agent_dir.join("index.jsonl");
    {
        let mut active = refreshes().lock().unwrap_or_else(|e| e.into_inner());
        if !active.insert(index_path.clone()) {
            return false;
        }
    }
    let cleanup_path = index_path.clone();
    let spawn = std::thread::Builder::new()
        .name("apiary-memory-refresh".into())
        .spawn(move || {
            if let Some(embedder) = bind_background_embedder(&manifest) {
                let embedder_id = embedder.id();
                if embedder_id.starts_with("ollama:")
                    && !embedder_is_warm(&embedder_id)
                    && embedder.embed("Apiary memory warmup").is_err()
                {
                    clear_embedder_warm(&embedder_id);
                    refreshes()
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .remove(&cleanup_path);
                    return;
                }
                let log = EpisodicLog::open(&agent_dir);
                let index = SemanticIndex::open(&agent_dir);
                let vaults = configured_vaults(&manifest);
                let _ = index.refresh(&log, &vaults, embedder.as_ref());
            }
            refreshes()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&cleanup_path);
        });
    if spawn.is_err() {
        refreshes()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&index_path);
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiary_core::custody::Custody;
    use apiary_core::log::Tier;
    use nostr::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingEmbedder {
        calls: AtomicUsize,
    }

    impl CountingEmbedder {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Embedder for CountingEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, crate::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            HashEmbedder.embed(text)
        }

        fn id(&self) -> String {
            "test:counting-hash".into()
        }
    }

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

    #[test]
    fn unchanged_vaults_do_no_content_work() {
        let dir = std::env::temp_dir().join(format!(
            "apiary-index-vault-projection-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let vault_dir = dir.join("vault");
        std::fs::create_dir_all(vault_dir.join("projects")).unwrap();
        std::fs::write(vault_dir.join("projects/plan.md"), "# Plan\n\nHoney launch").unwrap();
        let log = EpisodicLog::open(&dir);
        let index = SemanticIndex::open(&dir);
        let embedder = CountingEmbedder::new();
        let vaults = vec![apiary_core::manifest::VaultRef {
            name: "work".into(),
            path: vault_dir.to_string_lossy().into_owned(),
            kind: Some("markdown".into()),
        }];

        index.refresh(&log, &vaults, &embedder).unwrap();
        let initial = embedder.calls.load(Ordering::Relaxed);
        assert!(initial > 0);
        index.refresh(&log, &vaults, &embedder).unwrap();
        assert_eq!(embedder.calls.load(Ordering::Relaxed), initial);

        std::fs::write(
            vault_dir.join("projects/plan.md"),
            "# Plan\n\nHoney launch moved to Friday",
        )
        .unwrap();
        index.refresh(&log, &vaults, &embedder).unwrap();
        assert!(embedder.calls.load(Ordering::Relaxed) > initial);
        assert!(dir.join("index.vaults.json").is_file());
        std::fs::remove_dir_all(&dir).ok();
    }
}
