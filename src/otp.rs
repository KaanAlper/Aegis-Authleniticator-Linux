use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use url::Url;

use crate::vault::{EntryInfo, OtpType, VaultEntry};

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("Invalid Base32 secret: {0}")]
    InvalidSecret(String),
    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Invalid otpauth URI: {0}")]
    InvalidUri(String),
}

pub fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn current_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn decode_base32_secret(secret: &str) -> Result<Vec<u8>, OtpError> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(OtpError::InvalidSecret("Secret is empty".into()));
    }
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|e| OtpError::InvalidSecret(e.to_string()))
}

fn hmac_digest(algo: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>, OtpError> {
    match algo.to_ascii_uppercase().as_str() {
        "SHA1" | "SHA-1" => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key)
                .map_err(|e| OtpError::InvalidSecret(e.to_string()))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "SHA256" | "SHA-256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| OtpError::InvalidSecret(e.to_string()))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "SHA512" | "SHA-512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key)
                .map_err(|e| OtpError::InvalidSecret(e.to_string()))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        other => Err(OtpError::UnsupportedAlgorithm(other.to_string())),
    }
}

fn hotp_raw(secret: &[u8], algo: &str, counter: u64) -> Result<u32, OtpError> {
    let hash = hmac_digest(algo, secret, &counter.to_be_bytes())?;
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin_code = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    Ok(bin_code)
}

pub fn generate_hotp(secret: &[u8], algo: &str, digits: u32, counter: u64) -> Result<String, OtpError> {
    let raw = hotp_raw(secret, algo, counter)?;
    let modulo = 10u64.pow(digits);
    let code = (u64::from(raw)) % modulo;
    Ok(format!("{:0width$}", code, width = digits as usize))
}

pub fn generate_totp(
    secret: &[u8],
    algo: &str,
    digits: u32,
    period: u64,
    timestamp: u64,
) -> Result<String, OtpError> {
    let period = period.max(1);
    let counter = timestamp / period;
    generate_hotp(secret, algo, digits, counter)
}

pub fn generate_steam(secret: &[u8], timestamp: u64, period: u64, digits: u32) -> Result<String, OtpError> {
    let period = period.max(1);
    let counter = timestamp / period;
    let mut code = hotp_raw(secret, "SHA1", counter)?;
    let mut out = String::with_capacity(digits as usize);
    for _ in 0..digits {
        let idx = (code as usize) % STEAM_ALPHABET.len();
        out.push(STEAM_ALPHABET[idx] as char);
        code /= STEAM_ALPHABET.len() as u32;
    }
    Ok(out)
}

pub fn generate_motp(
    secret: &[u8],
    digits: u32,
    period: u64,
    pin: &str,
    timestamp: u64,
) -> Result<String, OtpError> {
    let period = period.max(1);
    let counter = timestamp / period;
    let secret_hex = hex::encode(secret);
    let to_digest = format!("{counter}{secret_hex}{pin}");
    let digest = Md5::digest(to_digest.as_bytes());
    let hex_digest = hex::encode(digest);
    Ok(hex_digest.chars().take(digits as usize).collect())
}

pub fn generate_yandex(
    secret: &[u8],
    pin: &str,
    digits: u32,
    algo: &str,
    period: u64,
    timestamp: u64,
) -> Result<String, OtpError> {
    let period = period.max(1);
    let mut pin_with_secret = Vec::with_capacity(pin.len() + secret.len());
    pin_with_secret.extend_from_slice(pin.as_bytes());
    pin_with_secret.extend_from_slice(secret);

    let key_hash_full = Sha256::digest(&pin_with_secret);
    let key_hash: &[u8] = if key_hash_full[0] == 0 {
        &key_hash_full[1..]
    } else {
        &key_hash_full[..]
    };

    let counter = timestamp / period;
    let mut period_hash = hmac_digest(algo, key_hash, &counter.to_be_bytes())?;
    let offset = (period_hash[period_hash.len() - 1] & 0x0f) as usize;
    period_hash[offset] &= 0x7f;

    let mut buf = [0u8; 8];
    buf.copy_from_slice(&period_hash[offset..offset + 8]);
    let otp = u64::from_be_bytes(buf);

    let alphabet_len = 26u64;
    let modulo = alphabet_len.pow(digits);
    let mut code = otp % modulo;
    let mut chars = vec!['a'; digits as usize];
    for i in (0..digits as usize).rev() {
        chars[i] = (b'a' + (code % alphabet_len) as u8) as char;
        code /= alphabet_len;
    }
    Ok(chars.into_iter().collect())
}

pub fn generate_code_for_entry(entry: &VaultEntry, timestamp: u64) -> Result<String, OtpError> {
    let secret = decode_base32_secret(&entry.info.secret)?;
    match entry.entry_type {
        OtpType::Totp => generate_totp(
            &secret,
            &entry.info.algo,
            entry.info.digits,
            entry.info.period.unwrap_or(30),
            timestamp,
        ),
        OtpType::Hotp => generate_hotp(
            &secret,
            &entry.info.algo,
            entry.info.digits,
            entry.info.counter.unwrap_or(0),
        ),
        OtpType::Steam => generate_steam(
            &secret,
            timestamp,
            entry.info.period.unwrap_or(30),
            entry.info.digits,
        ),
        OtpType::Motp => generate_motp(
            &secret,
            entry.info.digits,
            entry.info.period.unwrap_or(10),
            entry.info.pin.as_deref().unwrap_or(""),
            timestamp,
        ),
        OtpType::Yandex => generate_yandex(
            &secret,
            entry.info.pin.as_deref().unwrap_or(""),
            entry.info.digits,
            &entry.info.algo,
            entry.info.period.unwrap_or(30),
            timestamp,
        ),
    }
}

pub fn format_code_display(code: &str) -> String {
    let len = code.len();
    if len == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else if len == 8 {
        format!("{} {}", &code[..4], &code[4..])
    } else {
        code.to_string()
    }
}

pub fn parse_otpauth_uri(raw: &str) -> Result<VaultEntry, OtpError> {
    let trimmed = raw.trim();
    let url = Url::parse(trimmed).map_err(|e| OtpError::InvalidUri(e.to_string()))?;
    if url.scheme() != "otpauth" {
        return Err(OtpError::InvalidUri("Scheme must be otpauth://".into()));
    }

    let host = url
        .host_str()
        .ok_or_else(|| OtpError::InvalidUri("Missing OTP type".into()))?
        .to_ascii_lowercase();

    let entry_type = match host.as_str() {
        "totp" => OtpType::Totp,
        "hotp" => OtpType::Hotp,
        "steam" => OtpType::Steam,
        "motp" => OtpType::Motp,
        "yaotp" | "yandex" => OtpType::Yandex,
        other => return Err(OtpError::InvalidUri(format!("Unsupported type: {other}"))),
    };

    let raw_label = url.path().trim_start_matches('/');
    let decoded_label = percent_decode(raw_label);
    let (label_issuer, label_name) = if let Some((iss, acc)) = decoded_label.split_once(':') {
        (iss.trim().to_string(), acc.trim().to_string())
    } else {
        (String::new(), decoded_label.trim().to_string())
    };

    let mut secret = String::new();
    let mut issuer = label_issuer;
    let mut algo = "SHA1".to_string();
    let mut digits: u32 = if entry_type == OtpType::Steam { 5 } else { 6 };
    let mut period: Option<u64> = Some(30);
    let mut counter: Option<u64> = None;
    let mut pin: Option<String> = None;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "secret" => secret = v.trim().to_ascii_uppercase(),
            "issuer" if !v.trim().is_empty() => issuer = v.trim().to_string(),
            "algorithm" => algo = v.trim().to_ascii_uppercase(),
            "digits" => {
                if let Ok(d) = v.parse::<u32>() {
                    digits = d;
                }
            }
            "period" => {
                if let Ok(p) = v.parse::<u64>() {
                    period = Some(p.max(1));
                }
            }
            "counter" => {
                if let Ok(c) = v.parse::<u64>() {
                    counter = Some(c);
                }
            }
            "pin" => pin = Some(v.to_string()),
            _ => {}
        }
    }

    if secret.is_empty() {
        return Err(OtpError::InvalidUri("Missing secret parameter".into()));
    }
    decode_base32_secret(&secret)?;

    if entry_type == OtpType::Hotp {
        period = None;
        if counter.is_none() {
            counter = Some(0);
        }
    }

    Ok(VaultEntry {
        entry_type,
        uuid: uuid::Uuid::new_v4().to_string(),
        name: label_name,
        issuer,
        note: String::new(),
        favorite: false,
        icon: None,
        icon_mime: None,
        icon_hash: None,
        info: EntryInfo {
            secret,
            algo,
            digits,
            period,
            counter,
            pin,
        },
        groups: Vec::new(),
    })
}

fn percent_decode(input: &str) -> String {
    url::form_urlencoded::parse(format!("x={input}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| input.to_string())
}

pub fn decode_qr_from_image(path: &std::path::Path) -> Result<String, String> {
    let img = image::open(path).map_err(|e| format!("Failed to open image: {e}"))?;
    let luma = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(luma);
    let grids = prepared.detect_grids();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            return Ok(content);
        }
    }
    Err("No valid QR code found in image".to_string())
}

pub fn entry_to_otpauth_uri(entry: &VaultEntry) -> String {
    let typ = match entry.entry_type {
        OtpType::Totp => "totp",
        OtpType::Hotp => "hotp",
        OtpType::Steam => "steam",
        OtpType::Motp => "motp",
        OtpType::Yandex => "yaotp",
    };
    let label = if entry.issuer.is_empty() {
        entry.name.clone()
    } else if entry.name.is_empty() {
        entry.issuer.clone()
    } else {
        format!("{}:{}", entry.issuer, entry.name)
    };
    let enc_label: String = url::form_urlencoded::byte_serialize(label.as_bytes()).collect();
    let mut params = vec![
        format!("secret={}", entry.info.secret),
        format!("algorithm={}", entry.info.algo),
        format!("digits={}", entry.info.digits),
    ];
    if !entry.issuer.is_empty() {
        let enc_iss: String =
            url::form_urlencoded::byte_serialize(entry.issuer.as_bytes()).collect();
        params.push(format!("issuer={enc_iss}"));
    }
    if entry.entry_type == OtpType::Hotp {
        params.push(format!("counter={}", entry.info.counter.unwrap_or(0)));
    } else if let Some(p) = entry.info.period {
        params.push(format!("period={p}"));
    }
    format!("otpauth://{typ}/{enc_label}?{}", params.join("&"))
}

pub fn export_txt(entries: &[VaultEntry]) -> String {
    entries
        .iter()
        .map(entry_to_otpauth_uri)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn export_html(entries: &[VaultEntry]) -> String {
    let mut rows = String::new();
    for e in entries {
        let uri = entry_to_otpauth_uri(e);
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>\n",
            html_escape(&e.issuer),
            html_escape(&e.name),
            e.entry_type.label(),
            html_escape(&e.info.secret),
            html_escape(&uri),
        ));
    }
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Aegis Vault Export</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0d0f16; color: #e2e8f0; padding: 2rem; }}
h1 {{ color: #2095f2; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
th, td {{ border: 1px solid #282e41; padding: 10px; text-align: left; font-size: 13px; }}
th {{ background: #181c28; }}
code {{ word-break: break-all; color: #93c5fd; }}
</style>
</head>
<body>
<h1>Aegis Authenticator Export</h1>
<p>Total entries: {}</p>
<table>
<thead><tr><th>Issuer</th><th>Account</th><th>Type</th><th>Secret</th><th>otpauth URI</th></tr></thead>
<tbody>
{}
</tbody>
</table>
</body>
</html>"#,
        entries.len(),
        rows
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Encodes entries into Google Authenticator's `otpauth-migration://offline?data=...` format.
pub fn export_google_auth_migration(entries: &[VaultEntry]) -> String {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    fn write_varint(buf: &mut Vec<u8>, mut val: u64) {
        loop {
            let mut byte = (val & 0x7f) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if val == 0 {
                break;
            }
        }
    }

    fn write_bytes_field(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
        write_varint(buf, u64::from((field << 3) | 2));
        write_varint(buf, data.len() as u64);
        buf.extend_from_slice(data);
    }

    fn write_varint_field(buf: &mut Vec<u8>, field: u32, val: u64) {
        if val != 0 {
            write_varint(buf, u64::from(field << 3));
            write_varint(buf, val);
        }
    }

    let mut payload = Vec::new();
    for e in entries {
        let Ok(secret_bytes) = decode_base32_secret(&e.info.secret) else {
            continue;
        };
        let mut otp_param = Vec::new();
        write_bytes_field(&mut otp_param, 1, &secret_bytes);
        let label = if e.issuer.is_empty() {
            e.name.clone()
        } else if e.name.is_empty() {
            e.issuer.clone()
        } else {
            format!("{}:{}", e.issuer, e.name)
        };
        write_bytes_field(&mut otp_param, 2, label.as_bytes());
        if !e.issuer.is_empty() {
            write_bytes_field(&mut otp_param, 3, e.issuer.as_bytes());
        }
        let algo_num = match e.info.algo.to_ascii_uppercase().as_str() {
            "SHA256" => 2,
            "SHA512" => 3,
            "MD5" => 4,
            _ => 1,
        };
        write_varint_field(&mut otp_param, 4, algo_num);
        let digits_num = if e.info.digits == 8 { 2 } else { 1 };
        write_varint_field(&mut otp_param, 5, digits_num);
        let type_num = if e.entry_type == OtpType::Hotp { 1 } else { 2 };
        write_varint_field(&mut otp_param, 6, type_num);
        if e.entry_type == OtpType::Hotp {
            write_varint_field(&mut otp_param, 7, e.info.counter.unwrap_or(0));
        }
        write_bytes_field(&mut payload, 1, &otp_param);
    }

    write_varint_field(&mut payload, 2, 1); // version = 1
    write_varint_field(&mut payload, 3, 1); // batch_size = 1
    write_varint_field(&mut payload, 5, 1); // batch_id = 1

    let b64 = BASE64.encode(payload);
    let enc: String = url::form_urlencoded::byte_serialize(b64.as_bytes()).collect();
    format!("otpauth-migration://offline?data={enc}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4226_hotp() {
        // RFC 4226 test vector secret = "12345678901234567890"
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ];
        for (counter, exp) in expected.iter().enumerate() {
            let code = generate_hotp(secret, "SHA1", 6, counter as u64).unwrap();
            assert_eq!(&code, exp);
        }
    }

    #[test]
    fn test_rfc6238_totp() {
        let secret = b"12345678901234567890";
        assert_eq!(
            generate_totp(secret, "SHA1", 8, 30, 59).unwrap(),
            "94287082"
        );
        assert_eq!(
            generate_totp(secret, "SHA1", 8, 30, 1111111109).unwrap(),
            "07081804"
        );
    }

    #[test]
    fn test_steam_totp() {
        let secret = decode_base32_secret("JRZCL47CMXVOQMNPZR2F7J4RGI").unwrap();
        let code = generate_steam(&secret, 1700000000, 30, 5).unwrap();
        assert_eq!(code.len(), 5);
        assert!(code.chars().all(|c| STEAM_ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn test_parse_otpauth_uri() {
        let uri = "otpauth://totp/GitHub:kaanalper?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        let entry = parse_otpauth_uri(uri).unwrap();
        assert_eq!(entry.entry_type, OtpType::Totp);
        assert_eq!(entry.issuer, "GitHub");
        assert_eq!(entry.name, "kaanalper");
        assert_eq!(entry.info.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.info.digits, 6);
        assert_eq!(entry.info.period, Some(30));
    }
}

