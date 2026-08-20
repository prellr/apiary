//! Markdown vaults — knowledge folders as agent memory.
//!
//! An Obsidian vault IS a markdown folder; one engine serves both. The
//! `obsidian` flavor additionally understands YAML frontmatter, `#tags`,
//! and `[[wikilinks]]`. Vaults feed the agent two ways, and they compose:
//!
//! - **Ambient recall** — `memory.vaults` entries are chunked and embedded
//!   into the semantic index, so retrieval surfaces relevant notes into
//!   the working set beside the agent's own log memories (as DATA, per
//!   the provenance rule).
//! - **Tools** — the `obsidian` / `markdown-vault` connector kinds expose
//!   search/read (and write, only under an explicit cap) during runs.
//!
//! Every path is JAILED: canonicalized and required to stay under the
//! canonical vault root — `../` and symlink escapes fail closed.

use std::path::{Path, PathBuf};

/// Hard ceiling on notes walked per vault — a runaway folder should
/// degrade loudly, not hang runs.
const MAX_NOTES: usize = 5000;
const MAX_NOTE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone)]
pub struct NoteRef {
    /// Path relative to the vault root, forward slashes.
    pub rel: String,
    pub title: String,
}

/// A cheap inventory used by the derived-memory refresher. Directories are
/// retained so later checks can notice added/deleted notes without walking the
/// tree again; note contents are intentionally not read here.
#[derive(Debug, Clone)]
pub struct VaultInventory {
    pub notes: Vec<NoteRef>,
    /// Relative directory paths; the vault root is the empty string.
    pub directories: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub rel: String,
    pub title: String,
    pub snippet: String,
    /// Where it matched: "title" | "tag" | "content".
    pub matched: String,
}

/// Canonical root, or a loud error — a vault that doesn't exist is a
/// manifest mistake, not an empty result.
pub fn open_root(path: &str) -> Result<PathBuf, crate::Error> {
    let root = PathBuf::from(shellexpand_home(path));
    root.canonicalize()
        .map_err(|e| crate::Error::Provider(format!("vault '{path}': {e}")))
}

fn shellexpand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{rest}", home.to_string_lossy());
        }
    }
    p.to_string()
}

/// Resolve a note path INSIDE the jail. Rejects traversal and symlink
/// escapes by comparing canonical forms.
pub fn resolve(root: &Path, rel: &str) -> Result<PathBuf, crate::Error> {
    let joined = root.join(rel);
    let canon = joined
        .canonicalize()
        .map_err(|e| crate::Error::Provider(format!("note '{rel}': {e}")))?;
    if !canon.starts_with(root) {
        return Err(crate::Error::Provider(format!(
            "note '{rel}' escapes the vault — refused"
        )));
    }
    Ok(canon)
}

/// Walk the vault for markdown notes, skipping Obsidian metadata, trash,
/// and hidden directories.
pub fn inventory(root: &Path) -> Result<VaultInventory, crate::Error> {
    let mut out = Vec::new();
    let mut directories = vec![String::new()];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| crate::Error::Provider(format!("vault read {}: {e}", dir.display())))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue; // .obsidian, .trash, .git, hidden anything
            }
            if path.is_dir() {
                // Do not follow a directory symlink outside the jail while
                // discovering ambient memory.
                let Ok(canonical) = path.canonicalize() else {
                    continue;
                };
                if !canonical.starts_with(root) {
                    continue;
                }
                let relative = canonical
                    .strip_prefix(root)
                    .unwrap_or(&canonical)
                    .to_string_lossy()
                    .replace('\\', "/");
                directories.push(relative);
                stack.push(canonical);
            } else if name.ends_with(".md") {
                if out.len() >= MAX_NOTES {
                    return Err(crate::Error::Provider(format!(
                        "vault exceeds {MAX_NOTES} notes — narrow the path"
                    )));
                }
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(NoteRef {
                    title: name.trim_end_matches(".md").to_string(),
                    rel,
                });
            }
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    directories.sort();
    directories.dedup();
    Ok(VaultInventory {
        notes: out,
        directories,
    })
}

pub fn walk(root: &Path) -> Result<Vec<NoteRef>, crate::Error> {
    Ok(inventory(root)?.notes)
}

pub fn read_note(root: &Path, rel: &str) -> Result<String, crate::Error> {
    let path = resolve(root, rel)?;
    let meta = std::fs::metadata(&path).map_err(|e| crate::Error::Provider(e.to_string()))?;
    if meta.len() > MAX_NOTE_BYTES {
        return Err(crate::Error::Provider(format!(
            "note '{rel}' is {}KB — over the {}KB ceiling",
            meta.len() / 1024,
            MAX_NOTE_BYTES / 1024
        )));
    }
    std::fs::read_to_string(&path).map_err(|e| crate::Error::Provider(format!("note '{rel}': {e}")))
}

/// Split YAML frontmatter (between leading `---` fences) from the body.
pub fn split_frontmatter(content: &str) -> (Option<&str>, &str) {
    let Some(rest) = content.strip_prefix("---\n") else {
        return (None, content);
    };
    match rest.find("\n---") {
        Some(end) => {
            let body = rest[end + 4..].trim_start_matches('\n');
            (Some(&rest[..end]), body)
        }
        None => (None, content),
    }
}

/// Obsidian tags: frontmatter `tags:` plus inline `#tag` tokens.
pub fn tags(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (fm, body) = split_frontmatter(content);
    if let Some(fm) = fm {
        let mut in_tags = false;
        for line in fm.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("tags:") {
                in_tags = true;
                for tag in rest.trim().trim_matches(['[', ']'].as_ref()).split(',') {
                    let tag = tag.trim().trim_matches('"').trim_start_matches('#');
                    if !tag.is_empty() {
                        out.push(tag.to_lowercase());
                    }
                }
            } else if in_tags && t.starts_with("- ") {
                out.push(t[2..].trim().trim_start_matches('#').to_lowercase());
            } else if !t.starts_with("- ") {
                in_tags = false;
            }
        }
    }
    for word in body.split_whitespace() {
        if let Some(tag) = word.strip_prefix('#') {
            let tag: String = tag
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '/')
                .collect();
            if !tag.is_empty() && !tag.chars().all(|c| c.is_numeric()) {
                out.push(tag.to_lowercase());
            }
        }
    }
    out.dedup();
    out
}

/// `[[Wikilink]]` / `[[target|alias]]` targets in a note body.
pub fn wikilinks(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find("[[") {
        let Some(end) = rest[start + 2..].find("]]") else {
            break;
        };
        let inner = &rest[start + 2..start + 2 + end];
        let target = inner.split('|').next().unwrap_or(inner).trim();
        if !target.is_empty() {
            out.push(target.to_string());
        }
        rest = &rest[start + 2 + end + 2..];
    }
    out
}

/// Case-insensitive search across titles, tags (obsidian flavor), and
/// content, with a matched-line snippet.
pub fn search(
    root: &Path,
    query: &str,
    obsidian: bool,
    limit: usize,
) -> Result<Vec<SearchHit>, crate::Error> {
    let needle = query.to_lowercase();
    let mut hits = Vec::new();
    for note in walk(root)? {
        if hits.len() >= limit {
            break;
        }
        if note.title.to_lowercase().contains(&needle) {
            hits.push(SearchHit {
                rel: note.rel.clone(),
                title: note.title.clone(),
                snippet: String::new(),
                matched: "title".into(),
            });
            continue;
        }
        let Ok(content) = read_note(root, &note.rel) else {
            continue;
        };
        if obsidian && tags(&content).iter().any(|t| t.contains(&needle)) {
            hits.push(SearchHit {
                rel: note.rel.clone(),
                title: note.title.clone(),
                snippet: String::new(),
                matched: "tag".into(),
            });
            continue;
        }
        // Content means the BODY — frontmatter is metadata, not prose
        // (the obsidian flavor's tag search covers it deliberately).
        let (_, body) = split_frontmatter(&content);
        if let Some(line) = body.lines().find(|l| l.to_lowercase().contains(&needle)) {
            hits.push(SearchHit {
                rel: note.rel,
                title: note.title,
                snippet: line.trim().chars().take(200).collect(),
                matched: "content".into(),
            });
        }
    }
    Ok(hits)
}

/// Heading-aware chunks for the semantic index (~target_chars each).
pub fn chunks(content: &str, target_chars: usize) -> Vec<String> {
    let (_, body) = split_frontmatter(content);
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for block in body.split("\n\n") {
        let starts_section = block.trim_start().starts_with('#');
        if !cur.is_empty() && (cur.len() + block.len() > target_chars || starts_section) {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push_str("\n\n");
        }
        cur.push_str(block.trim());
        // A single oversized block still flushes.
        if cur.len() >= target_chars {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out.retain(|c| !c.trim().is_empty());
    out
}

/// Short content fingerprint for staleness-aware index rows.
pub fn fingerprint(content: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(content.as_bytes()))
        .chars()
        .take(8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("apiary-vault-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("projects")).unwrap();
        std::fs::create_dir_all(d.join(".obsidian")).unwrap();
        std::fs::write(
            d.join("projects/honey.md"),
            "---\ntags: [winter, launch]\n---\n# Honey\nShips in [[November Plan|November]]. #beekeeping\n",
        )
        .unwrap();
        std::fs::write(d.join("scratch.md"), "just a plain note about wax\n").unwrap();
        std::fs::write(d.join(".obsidian/app.json"), "{}").unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn walk_skips_metadata_and_search_finds_all_ways() {
        let root = vault("walk");
        let notes = walk(&root).unwrap();
        assert_eq!(notes.len(), 2);
        assert!(notes.iter().all(|n| !n.rel.contains(".obsidian")));
        assert_eq!(
            search(&root, "honey", true, 10).unwrap()[0].matched,
            "title"
        );
        assert_eq!(search(&root, "winter", true, 10).unwrap()[0].matched, "tag");
        assert_eq!(
            search(&root, "wax", true, 10).unwrap()[0].matched,
            "content"
        );
        // markdown flavor: no tag matching
        assert!(search(&root, "winter", false, 10).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn jail_refuses_escapes() {
        let root = vault("jail");
        assert!(read_note(&root, "projects/honey.md").is_ok());
        assert!(read_note(&root, "../outside.md").is_err());
        assert!(read_note(&root, "projects/../../outside.md").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn obsidian_semantics() {
        let content =
            "---\ntags: [winter, launch]\n---\n# H\nSee [[November Plan|Nov]]. #beekeeping x\n";
        assert_eq!(tags(content), vec!["winter", "launch", "beekeeping"]);
        assert_eq!(wikilinks(content), vec!["November Plan"]);
        let (fm, body) = split_frontmatter(content);
        assert!(fm.unwrap().contains("tags"));
        assert!(body.starts_with("# H"));
    }

    #[test]
    fn chunking_respects_headings() {
        let long = format!("# A\n\n{}\n\n# B\n\nshort", "x".repeat(50));
        let ch = chunks(&long, 1000);
        assert_eq!(ch.len(), 2);
        assert!(ch[1].starts_with("# B"));
    }
}
