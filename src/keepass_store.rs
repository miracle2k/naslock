use anyhow::{Context, Result, bail};
use keepass::db::{Entry, NodeRef};
use keepass::{Database, DatabaseKey};
use std::fs::File;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct KeePassStore {
    db: Database,
}

impl KeePassStore {
    pub fn open(path: &Path, key_file: Option<&Path>, password: &str) -> Result<Self> {
        let mut db_file = File::open(path)
            .with_context(|| format!("failed to open KeePass DB {}", path.display()))?;

        let mut key = DatabaseKey::new().with_password(password);
        if let Some(key_file_path) = key_file {
            let mut key_file = File::open(key_file_path)
                .with_context(|| format!("failed to open key file {}", key_file_path.display()))?;
            key = key.with_keyfile(&mut key_file)?;
        }

        let db = Database::open(&mut db_file, key)
            .with_context(|| format!("failed to open KeePass DB {}", path.display()))?;
        Ok(Self { db })
    }

    pub fn find_entry<'a>(&'a self, selector: &str) -> Option<&'a Entry> {
        let selector = selector.trim();
        let (mode, token) = parse_selector(selector);
        match mode {
            SelectorMode::Uuid => {
                let uuid = parse_uuid(token)?;
                for node in &self.db.root {
                    if let NodeRef::Entry(entry) = node {
                        if entry.get_uuid() == &uuid {
                            return Some(entry);
                        }
                    }
                }
                None
            }
            SelectorMode::Title => {
                for node in &self.db.root {
                    if let NodeRef::Entry(entry) = node {
                        if let Some(title) = entry.get_title() {
                            if title == token {
                                return Some(entry);
                            }
                        }
                    }
                }
                None
            }
            SelectorMode::Auto => {
                let uuid = parse_uuid(token);
                for node in &self.db.root {
                    if let NodeRef::Entry(entry) = node {
                        if let Some(uuid) = uuid {
                            if entry.get_uuid() == &uuid {
                                return Some(entry);
                            }
                        }
                        if let Some(title) = entry.get_title() {
                            if title == token {
                                return Some(entry);
                            }
                        }
                    }
                }
                None
            }
        }
    }
}

pub fn required_field(entry: &Entry, field: &str, entry_label: &str) -> Result<Zeroizing<String>> {
    let value = entry_field(entry, field)
        .with_context(|| format!("missing field '{}' in KeePass entry {}", field, entry_label))?;
    Ok(Zeroizing::new(value.to_string()))
}

pub fn entry_field<'a>(entry: &'a Entry, field: &str) -> Option<&'a str> {
    let field_trimmed = field.trim();
    let field_lower = field_trimmed.to_ascii_lowercase();
    match field_lower.as_str() {
        "title" => entry.get_title(),
        "username" | "user_name" | "user-name" | "user" => entry.get_username(),
        "password" | "pass" => entry.get_password(),
        "url" => entry.get_url(),
        _ => entry.get(field_trimmed),
    }
}

fn parse_selector(input: &str) -> (SelectorMode, &str) {
    let lowered = input.to_ascii_lowercase();
    if let Some(rest) = lowered.strip_prefix("uuid:") {
        let original = &input[input.len() - rest.len()..];
        return (SelectorMode::Uuid, original.trim());
    }
    if let Some(rest) = lowered.strip_prefix("title:") {
        let original = &input[input.len() - rest.len()..];
        return (SelectorMode::Title, original.trim());
    }
    (SelectorMode::Auto, input)
}

fn parse_uuid(input: &str) -> Option<Uuid> {
    let trimmed = input.trim().trim_matches('{').trim_matches('}');
    if let Ok(uuid) = Uuid::parse_str(trimmed) {
        return Some(uuid);
    }
    let cleaned: String = trimmed.chars().filter(|c| *c != '-').collect();
    if cleaned.len() == 32 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        Uuid::parse_str(&cleaned).ok()
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectorMode {
    Auto,
    Title,
    Uuid,
}

pub fn require_entry<'a>(store: &'a KeePassStore, selector: &str) -> Result<&'a Entry> {
    store
        .find_entry(selector)
        .with_context(|| format!("KeePass entry not found: {}", selector))
}

pub fn ensure_non_empty(secret: &str, label: &str) -> Result<()> {
    if secret.trim().is_empty() {
        bail!("empty secret for {}", label);
    }
    Ok(())
}
