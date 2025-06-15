use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// JA4 signature entry from database
#[derive(Debug, Clone)]
pub struct Ja4Entry {
    pub ja4_hash: String,
    pub application: String,
    pub os: String,
    pub device: String,
}

/// JA4 signature database
#[derive(Debug)]
pub struct Ja4Database {
    entries: HashMap<String, Ja4Entry>,
}

impl Ja4Database {
    /// Create a new empty JA4 database
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Load JA4 signatures from CSV file
    pub fn load_from_csv<P: AsRef<Path>>(csv_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(csv_path)?;
        let mut db = Self::new();

        // Skip header line
        for (line_num, line) in content.lines().enumerate().skip(1) {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                let entry = Ja4Entry {
                    ja4_hash: parts[0].trim().to_string(),
                    application: parts[1].trim().to_string(),
                    os: parts[2].trim().to_string(),
                    device: parts[3].trim().to_string(),
                };

                db.entries.insert(entry.ja4_hash.clone(), entry);
            } else {
                eprintln!(
                    "Warning: Invalid CSV line {} (expected 4 columns): {}",
                    line_num + 1,
                    line
                );
            }
        }

        println!("Loaded {} JA4 signatures from database", db.entries.len());
        Ok(db)
    }

    /// Look up a JA4 hash in the database
    pub fn lookup(&self, ja4_hash: &str) -> Option<&Ja4Entry> {
        self.entries.get(ja4_hash)
    }

    /// Get all entries in the database
    pub fn all_entries(&self) -> impl Iterator<Item = &Ja4Entry> {
        self.entries.values()
    }

    /// Get the number of entries in the database
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for Ja4Database {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_csv() {
        let csv_content = "ja4,application,os,device\n25b178d9318e,Chrome,Windows,Desktop\na82c4b5e7f12,Firefox,Linux,Desktop\n";

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(csv_content.as_bytes()).unwrap();

        let db = Ja4Database::load_from_csv(temp_file.path()).unwrap();
        assert_eq!(db.len(), 2);

        let entry = db.lookup("25b178d9318e").unwrap();
        assert_eq!(entry.application, "Chrome");
        assert_eq!(entry.os, "Windows");
        assert_eq!(entry.device, "Desktop");
    }

    #[test]
    fn test_lookup_nonexistent() {
        let db = Ja4Database::new();
        assert!(db.lookup("nonexistent").is_none());
    }
}
