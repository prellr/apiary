//! Atomic, revision-checked persistence for an agent's constitutional state.
//!
//! Handlers may validate and prepare an amendment outside the file lock, but
//! they must present the exact manifest revision they read. This turns a
//! concurrent edit into a visible conflict instead of silently overwriting it.

use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StoreError {
    Conflict { current_revision: String },
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { .. } => write!(
                formatter,
                "the agent changed while this amendment was being prepared; reload and try again"
            ),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn revision(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

/// Replace `manifest.yaml` only when it still matches the revision the
/// caller read. The lock file also coordinates independent host processes.
pub fn replace_manifest(
    agent_dir: &Path,
    expected_raw: &str,
    replacement: &str,
) -> Result<String, StoreError> {
    let manifest_path = agent_dir.join("manifest.yaml");
    let lock_path = agent_dir.join("manifest.lock");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    lock.lock_exclusive()?;

    let result = (|| {
        let current = std::fs::read_to_string(&manifest_path)?;
        if current != expected_raw {
            return Err(StoreError::Conflict {
                current_revision: revision(&current),
            });
        }
        atomic_replace(&manifest_path, replacement.as_bytes())?;
        Ok(revision(replacement))
    })();
    let _ = FileExt::unlock(&lock);
    result
}

/// Create the first manifest for a newly founded agent without replacing an
/// existing identity's state.
pub fn create_manifest(agent_dir: &Path, yaml: &str) -> Result<String, StoreError> {
    let manifest_path = agent_dir.join("manifest.yaml");
    let lock_path = agent_dir.join("manifest.lock");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    lock.lock_exclusive()?;
    let result = if manifest_path.exists() {
        let current = std::fs::read_to_string(&manifest_path)?;
        Err(StoreError::Conflict {
            current_revision: revision(&current),
        })
    } else {
        atomic_replace(&manifest_path, yaml.as_bytes())?;
        Ok(revision(yaml))
    };
    let _ = FileExt::unlock(&lock);
    result
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "manifest has no parent")
    })?;
    let temporary = temporary_path(path);
    let write_result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result
}

fn temporary_path(path: &Path) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!("yaml.tmp-{}-{nonce}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "apiary-agent-store-{name}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn rejects_a_stale_amendment() {
        let dir = fixture("conflict");
        std::fs::write(dir.join("manifest.yaml"), "first").unwrap();
        replace_manifest(&dir, "first", "second").unwrap();
        let error = replace_manifest(&dir, "first", "stale").unwrap_err();
        assert!(matches!(error, StoreError::Conflict { .. }));
        assert_eq!(
            std::fs::read_to_string(dir.join("manifest.yaml")).unwrap(),
            "second"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn writes_complete_replacement() {
        let dir = fixture("replace");
        std::fs::write(dir.join("manifest.yaml"), "old").unwrap();
        let revision = replace_manifest(&dir, "old", "new manifest").unwrap();
        assert_eq!(revision, super::revision("new manifest"));
        assert_eq!(
            std::fs::read_to_string(dir.join("manifest.yaml")).unwrap(),
            "new manifest"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
