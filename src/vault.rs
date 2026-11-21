use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const DEFAULT_SCRYPT_N: u32 = 32768;
pub const DEFAULT_SCRYPT_R: u32 = 8;
pub const DEFAULT_SCRYPT_P: u32 = 1;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid vault version: {0}")]
    UnsupportedVersion(u32),
    #[error("Vault is encrypted and requires a password")]
    PasswordRequired,
    #[error("Incorrect password or corrupted vault")]
    InvalidPassword,
    #[error("Invalid cryptographic parameters: {0}")]
    Crypto(String),
    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub header: VaultHeader,
    pub db: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultHeader {
    pub slots: Option<Vec<KeySlot>>,
    pub params: Option<CipherParams>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub nonce: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    #[serde(rename = "type")]
    pub slot_type: u8,
    pub uuid: String,
    pub key: String,
    pub key_params: CipherParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repaired: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultDb {
    #[serde(default = "default_db_version")]
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<VaultEntry>,
    #[serde(default)]
    pub groups: Vec<VaultGroup>,
}

fn default_db_version() -> u32 {
    3
}

impl Default for VaultDb {
    fn default() -> Self {
        Self {
            version: 3,
            entries: Vec::new(),
            groups: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OtpType {
    Totp,
    Hotp,
    Steam,
    Motp,
    Yandex,
}

impl OtpType {
    pub fn label(&self) -> &'static str {
        match self {
            OtpType::Totp => "TOTP",
            OtpType::Hotp => "HOTP",
            OtpType::Steam => "Steam",
            OtpType::Motp => "MOTP",
            OtpType::Yandex => "Yandex",
        }
    }

    pub fn all() -> &'static [OtpType] {
        &[
            OtpType::Totp,
            OtpType::Hotp,
            OtpType::Steam,
            OtpType::Motp,
            OtpType::Yandex,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryInfo {
    pub secret: String,
    #[serde(default = "default_algo")]
    pub algo: String,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

fn default_algo() -> String {
    "SHA1".to_string()
}

fn default_digits() -> u32 {
    6
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    #[serde(rename = "type")]
    pub entry_type: OtpType,
    pub uuid: String,
    pub name: String,
    pub issuer: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub icon_mime: Option<String>,
    #[serde(default)]
    pub icon_hash: Option<String>,
    pub info: EntryInfo,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultGroup {
    pub uuid: String,
    pub name: String,
}

impl VaultEntry {
    #[allow(dead_code)]
    pub fn new_totp(issuer: String, name: String, secret: String) -> Self {
        Self {
            entry_type: OtpType::Totp,
            uuid: Uuid::new_v4().to_string(),
            name,
            issuer,
            note: String::new(),
            favorite: false,
            icon: None,
            icon_mime: None,
            icon_hash: None,
            info: EntryInfo {
                secret,
                algo: "SHA1".to_string(),
                digits: 6,
                period: Some(30),
                counter: None,
                pin: None,
            },
            groups: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnlockedVault {
    pub db: VaultDb,
    pub master_key: Option<Zeroizing<[u8; 32]>>,
    pub header: VaultHeader,
}

impl UnlockedVault {
    pub fn new_plain() -> Self {
        Self {
            db: VaultDb::default(),
            master_key: None,
            header: VaultHeader {
                slots: None,
                params: None,
            },
        }
    }

    pub fn new_encrypted(password: &str) -> Result<Self, VaultError> {
        let mut vault = Self::new_plain();
        vault.set_password(Some(password))?;
        Ok(vault)
    }

    pub fn is_encrypted(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn set_password(&mut self, password: Option<&str>) -> Result<(), VaultError> {
        match password {
            None => {
                self.master_key = None;
                self.header = VaultHeader {
                    slots: None,
                    params: None,
                };
                Ok(())
            }
            Some(pwd) => {
                let mut mk = Zeroizing::new([0u8; 32]);
                if let Some(existing_mk) = &self.master_key {
                    mk.copy_from_slice(&existing_mk[..]);
                } else {
                    rand::thread_rng().fill_bytes(&mut mk[..]);
                }

                let new_slot = create_password_slot(pwd, &mk)?;

                // Keep non-password slots (e.g. biometric) if master key was unchanged
                let mut slots = if self.master_key.is_some() {
                    self.header
                        .slots
                        .clone()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|s| s.slot_type != 1)
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                slots.insert(0, new_slot);

                self.master_key = Some(mk);
                self.header.slots = Some(slots);
                Ok(())
            }
        }
    }

    pub fn to_vault_file(&self) -> Result<VaultFile, VaultError> {
        let mut db_to_save = self.db.clone();
        if db_to_save.version < 3 {
            db_to_save.version = 3;
        }

        if let Some(mk) = &self.master_key {
            let plaintext = serde_json::to_vec(&db_to_save)?;
            let (ciphertext, nonce_bytes, tag_bytes) = encrypt_aes_gcm(mk, &plaintext)?;

            let mut header = self.header.clone();
            header.params = Some(CipherParams {
                nonce: hex::encode(nonce_bytes),
                tag: hex::encode(tag_bytes),
            });

            Ok(VaultFile {
                version: 1,
                header,
                db: serde_json::Value::String(BASE64.encode(ciphertext)),
            })
        } else {
            Ok(VaultFile {
                version: 1,
                header: VaultHeader {
                    slots: None,
                    params: None,
                },
                db: serde_json::to_value(&db_to_save)?,
            })
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), VaultError> {
        let vault_file = self.to_vault_file()?;
        let json = serde_json::to_string_pretty(&vault_file)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        // Atomic-ish write via temp file in the same directory
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, json.as_bytes())?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

pub fn is_vault_file_encrypted(path: &Path) -> Result<bool, VaultError> {
    let content = fs::read_to_string(path)?;
    let vf: VaultFile = serde_json::from_str(&content)?;
    if vf.version != 1 {
        return Err(VaultError::UnsupportedVersion(vf.version));
    }
    Ok(vf.header.slots.is_some() && vf.header.params.is_some() && vf.db.is_string())
}

pub fn load_vault(path: &Path, password: Option<&str>) -> Result<UnlockedVault, VaultError> {
    let content = fs::read_to_string(path)?;
    parse_vault_str(&content, password)
}

pub fn parse_vault_str(content: &str, password: Option<&str>) -> Result<UnlockedVault, VaultError> {
    let vf: VaultFile = serde_json::from_str(content)?;
    if vf.version != 1 {
        return Err(VaultError::UnsupportedVersion(vf.version));
    }

    let is_encrypted = vf.header.slots.is_some() && vf.header.params.is_some() && vf.db.is_string();
    if !is_encrypted {
        let db: VaultDb = serde_json::from_value(vf.db)?;
        return Ok(UnlockedVault {
            db,
            master_key: None,
            header: vf.header,
        });
    }

    let pwd = password.ok_or(VaultError::PasswordRequired)?;
    let slots = vf
        .header
        .slots
        .as_ref()
        .ok_or_else(|| VaultError::Crypto("Missing header slots".into()))?;
    let db_params = vf
        .header
        .params
        .as_ref()
        .ok_or_else(|| VaultError::Crypto("Missing header params".into()))?;

    let mut master_key: Option<Zeroizing<[u8; 32]>> = None;
    for slot in slots.iter().filter(|s| s.slot_type == 1) {
        if let Some(mk) = try_decrypt_password_slot(slot, pwd)? {
            master_key = Some(mk);
            break;
        }
    }

    let mk = master_key.ok_or(VaultError::InvalidPassword)?;

    let db_b64 = vf
        .db
        .as_str()
        .ok_or_else(|| VaultError::Crypto("Encrypted db must be base64 string".into()))?;
    let ciphertext = BASE64.decode(db_b64)?;
    let nonce_bytes = hex::decode(&db_params.nonce)?;
    let tag_bytes = hex::decode(&db_params.tag)?;

    let plaintext = decrypt_aes_gcm(&mk, &ciphertext, &nonce_bytes, &tag_bytes)
        .map_err(|_| VaultError::InvalidPassword)?;
    let db: VaultDb = serde_json::from_slice(&plaintext)?;

    Ok(UnlockedVault {
        db,
        master_key: Some(mk),
        header: vf.header,
    })
}

fn try_decrypt_password_slot(
    slot: &KeySlot,
    password: &str,
) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
    let n = slot.n.unwrap_or(DEFAULT_SCRYPT_N);
    let r = slot.r.unwrap_or(DEFAULT_SCRYPT_R);
    let p = slot.p.unwrap_or(DEFAULT_SCRYPT_P);
    let salt_hex = slot
        .salt
        .as_deref()
        .ok_or_else(|| VaultError::Crypto("Password slot missing salt".into()))?;
    let salt = hex::decode(salt_hex)?;

    if !n.is_power_of_two() {
        return Err(VaultError::Crypto("scrypt N must be a power of two".into()));
    }
    let log_n = n.trailing_zeros() as u8;
    let params = ScryptParams::new(log_n, r, p, 32)
        .map_err(|e| VaultError::Crypto(format!("scrypt params error: {e}")))?;

    let mut derived = Zeroizing::new([0u8; 32]);
    scrypt(password.as_bytes(), &salt, &params, &mut derived[..])
        .map_err(|e| VaultError::Crypto(format!("scrypt error: {e}")))?;

    let key_ct = hex::decode(&slot.key)?;
    let nonce_bytes = hex::decode(&slot.key_params.nonce)?;
    let tag_bytes = hex::decode(&slot.key_params.tag)?;

    match decrypt_aes_gcm(&derived, &key_ct, &nonce_bytes, &tag_bytes) {
        Ok(mk_vec) => {
            if mk_vec.len() != 32 {
                return Err(VaultError::Crypto("Invalid master key length".into()));
            }
            let mut mk = Zeroizing::new([0u8; 32]);
            mk.copy_from_slice(&mk_vec);
            Ok(Some(mk))
        }
        Err(_) => Ok(None),
    }
}

fn create_password_slot(password: &str, master_key: &[u8; 32]) -> Result<KeySlot, VaultError> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    let log_n = DEFAULT_SCRYPT_N.trailing_zeros() as u8;
    let params = ScryptParams::new(log_n, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P, 32)
        .map_err(|e| VaultError::Crypto(format!("scrypt params error: {e}")))?;

    let mut derived = Zeroizing::new([0u8; 32]);
    scrypt(password.as_bytes(), &salt, &params, &mut derived[..])
        .map_err(|e| VaultError::Crypto(format!("scrypt error: {e}")))?;

    let (ct, nonce, tag) = encrypt_aes_gcm(&derived, master_key)?;

    Ok(KeySlot {
        slot_type: 1,
        uuid: Uuid::new_v4().to_string(),
        key: hex::encode(ct),
        key_params: CipherParams {
            nonce: hex::encode(nonce),
            tag: hex::encode(tag),
        },
        n: Some(DEFAULT_SCRYPT_N),
        r: Some(DEFAULT_SCRYPT_R),
        p: Some(DEFAULT_SCRYPT_P),
        salt: Some(hex::encode(salt)),
        repaired: None,
    })
}

fn encrypt_aes_gcm(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("AES key error: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut combined = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Crypto(format!("AES-GCM encrypt error: {e}")))?;

    if combined.len() < 16 {
        return Err(VaultError::Crypto("Ciphertext too short".into()));
    }
    let tag_start = combined.len() - 16;
    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(&combined[tag_start..]);
    combined.truncate(tag_start);

    Ok((combined, nonce_bytes, tag_bytes))
}

fn decrypt_aes_gcm(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    tag_bytes: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if nonce_bytes.len() != 12 || tag_bytes.len() != 16 {
        return Err(VaultError::Crypto("Invalid nonce or tag length".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("AES key error: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut combined = Vec::with_capacity(ciphertext.len() + tag_bytes.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag_bytes);

    cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| VaultError::InvalidPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_official_plain_vault() {
        let json = include_str!("../test_data/aegis_plain.json");
        let vault = parse_vault_str(json, None).expect("plain vault should parse");
        assert!(!vault.is_encrypted());
        assert_eq!(vault.db.entries.len(), 7);
        assert_eq!(vault.db.entries[0].issuer, "Deno");
        assert_eq!(vault.db.entries[6].entry_type, OtpType::Steam);
    }

    #[test]
    fn test_parse_official_encrypted_vault() {
        let json = include_str!("../test_data/aegis_encrypted.json");
        assert!(matches!(
            parse_vault_str(json, None),
            Err(VaultError::PasswordRequired)
        ));
        assert!(matches!(
            parse_vault_str(json, Some("wrong")),
            Err(VaultError::InvalidPassword)
        ));

        let vault = parse_vault_str(json, Some("test")).expect("encrypted vault should decrypt");
        assert!(vault.is_encrypted());
        assert_eq!(vault.db.entries.len(), 7);
        assert_eq!(vault.db.entries[0].issuer, "Deno");
    }

    #[test]
    fn test_encrypt_roundtrip() {
        let mut vault = UnlockedVault::new_encrypted("my-secret-pass").unwrap();
        vault.db.entries.push(VaultEntry::new_totp(
            "GitHub".into(),
            "kaanalper".into(),
            "JBSWY3DPEHPK3PXP".into(),
        ));
        let vf = vault.to_vault_file().unwrap();
        let serialized = serde_json::to_string(&vf).unwrap();

        let decrypted = parse_vault_str(&serialized, Some("my-secret-pass")).unwrap();
        assert_eq!(decrypted.db.entries.len(), 1);
        assert_eq!(decrypted.db.entries[0].issuer, "GitHub");
        assert_eq!(decrypted.db.entries[0].name, "kaanalper");
    }
}

