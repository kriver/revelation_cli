use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use chrono::TimeZone;
use chrono::{offset::Local, DateTime};
use compress::zlib::Decoder;
use regex::Regex;
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};
use std::path::PathBuf;

/*
 * From: https://github.com/mikelolasagasti/revelation/blob/65c191a8a496f8bcfc9ff85d79715bf56ed33c2d/src/lib/datahandler/rvl.py#L375
 *
 * Only supporting v2 Revelation files.
 */

#[derive(Debug)]
struct Entry {
    entry_type: String,
    name: String,
    description: Option<String>,
    updated: DateTime<Local>,
    notes: String,
    // example keys: generic-url, generic-username, generic-email, generic-password
    fields: HashMap<String, String>,
}

impl Entry {
    fn new(entry_type: &str, name: &str, description: &str, updated: &str, notes: &str) -> Self {
        Entry {
            entry_type: entry_type.to_owned(),
            name: name.to_owned(),
            description: (!description.is_empty()).then(|| description.to_owned()),
            updated: Local
                .timestamp_opt(updated.parse::<i64>().unwrap(), 0)
                .unwrap(),
            notes: notes.to_owned(),
            fields: HashMap::new(),
        }
    }
}

impl Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", &self.name, &self.entry_type)?;
        if let Some(d) = &self.description {
            write!(f, " \"{}\"", d)?;
        }
        Ok(())
    }
}

pub struct Safe {
    filename: PathBuf,
    entries: Vec<Entry>,
}

type HmacSha1 = hmac::Hmac<sha1::Sha1>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

impl Safe {
    pub fn new(filename: PathBuf) -> Self {
        Safe {
            filename,
            entries: Vec::new(),
        }
    }

    fn invalid(msg: &str) -> Error {
        Error::new(ErrorKind::InvalidData, msg)
    }

    /**
     * Format:
     * - magic string        : "rvl\x00"
     * - data version        : "\x02"
     * - separator           : "\x00"
     * - application version : 3 bytes
     * - separator           : "\x00"
     */
    fn validate_header(f: &mut File) -> Result<()> {
        let mut header = [0u8; 12];
        f.read_exact(&mut header)?;
        if !header.starts_with(b"rvl\x00\x02\x00") || header[11] != 0 {
            Err(Safe::invalid("invalid header found"))
        } else {
            Ok(())
        }
    }

    fn extract_cipher(&self, f: &mut File, password: &[u8]) -> Result<Aes256CbcDec> {
        let mut salt = [0u8; 8];
        let mut iv = [0u8; 16];
        let mut key = [0u8; 32];
        f.read_exact(&mut salt)?;
        f.read_exact(&mut iv)?;
        pbkdf2::pbkdf2::<HmacSha1>(password, &salt, 12000, &mut key);
        let cipher = Aes256CbcDec::new(&key.into(), &iv.into());
        Ok(cipher)
    }

    fn validate_body(expect: &[u8], body: &[u8]) -> Result<()> {
        let hash: [u8; 32] = Sha256::digest(body).into();
        if hash != expect {
            Err(Safe::invalid("invalid data digest"))
        } else {
            Ok(())
        }
    }

    fn decode(data: &mut [u8], cipher: Aes256CbcDec) -> Result<Vec<u8>> {
        if data.len() % 16 != 0 {
            Err(Safe::invalid("invalid encrypted data length"))
        } else {
            match cipher.decrypt_padded_mut::<Pkcs7>(data) {
                Err(e) => Err(Safe::invalid(&format!("decryption failed ({:?})", e))),
                Ok(_) => {
                    let hash = &data[0..32];
                    let data = &data[32..];
                    Safe::validate_body(hash, data)?;
                    let mut decoded = Vec::new();
                    Decoder::new(data).read_to_end(&mut decoded)?;
                    if !decoded.starts_with("<?xml".as_bytes()) {
                        Err(Safe::invalid("invalid content found"))
                    } else {
                        Ok(decoded)
                    }
                }
            }
        }
    }

    fn parse_child<'a>(node: &'a Node, name: &str) -> &'a str {
        node.children()
            .find(|n| n.has_tag_name(name))
            .unwrap()
            .text()
            .unwrap_or(&"")
    }

    fn parse_field(entry: &mut Entry, node: &Node) {
        entry.fields.insert(
            node.attribute("id").unwrap().to_owned(),
            node.text().unwrap_or("").to_owned(),
        );
    }

    fn parse_entry(&mut self, node: &Node) {
        let mut entry = Entry::new(
            node.attribute("type").unwrap(),
            Safe::parse_child(node, "name"),
            Safe::parse_child(node, "description"),
            Safe::parse_child(node, "updated"),
            Safe::parse_child(node, "notes"),
        );
        for field in node.children().filter(|n| n.has_tag_name("field")) {
            Safe::parse_field(&mut entry, &field);
        }
        self.entries.push(entry);
    }

    fn parse(&mut self, xml: &str) -> Result<()> {
        match Document::parse(xml) {
            Err(e) => Err(Safe::invalid(&format!("invalid XML ({:?})", e))),
            Ok(doc) => {
                for entry in doc.descendants().filter(|n| n.has_tag_name("entry")) {
                    self.parse_entry(&entry);
                }
                Ok(())
            }
        }
    }

    pub fn load<F>(&mut self, pw: F) -> Result<()>
    where
        F: Fn() -> String,
    {
        let mut f = File::open(&self.filename)?;
        Safe::validate_header(&mut f)?;
        let cipher = self.extract_cipher(&mut f, pw().as_bytes())?;
        let mut data: Vec<u8> = Vec::new();
        drop(f.read_to_end(&mut data));
        let decoded = Safe::decode(&mut data, cipher)?;
        let xml = std::str::from_utf8(&decoded).unwrap();
        self.parse(&xml)?;
        Ok(())
    }

    pub fn list(&self, regex: Option<Regex>, show_pw: bool) {
        println!("Found entries:");
        let mut cnt = 0;
        for entry in &self.entries {
            if regex
                .as_ref()
                .map(|re| re.is_match(&entry.name))
                .unwrap_or(true)
            {
                println!(" - {}", entry);
                if show_pw {
                    println!(
                        "   Password: '{}'",
                        entry
                            .fields
                            .get("generic-password")
                            .unwrap_or(&"<not-found>".to_owned())
                    );
                }
                cnt += 1;
            }
        }
        println!("Matched {}/{}", cnt, self.entries.len());
    }
}
