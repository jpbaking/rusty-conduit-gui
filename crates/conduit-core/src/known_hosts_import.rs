//! Manual, user-initiated import from an OpenSSH `known_hosts` file.
//!
//! This module only parses text it is handed. It never opens a file, and nothing in the app
//! reads `~/.ssh/known_hosts` automatically: the caller passes the content of a file the user
//! chose explicitly.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use ring::{digest, hmac};

/// One host key found in a `known_hosts` file for a requested host and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedHostKey {
    /// The key type, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// `SHA256:<standard-base64-no-pad>`, matching `ssh-keygen -l`.
    pub fingerprint_sha256: String,
    /// `<algorithm> <base64>`.
    pub public_key: String,
}

/// Returns every key in `content` whose host patterns match `host` on `port`, in file order.
///
/// Skips blank lines, `#` comments, `@revoked` and `@cert-authority` lines, malformed lines,
/// and keys whose base64 blob is invalid or does not name the stated key type. A line is
/// excluded when one of its `!pattern` negations matches. Plain patterns match port 22 only;
/// `[host]:port` matches that exact port. Hashed `|1|<salt>|<hmac-sha1>` entries are matched
/// against `host` (port 22) or `[host]:port` (other ports). Wildcards are not expanded.
pub fn parse_openssh_known_hosts_for_host(content: &str, host: &str, port: u16) -> Vec<ImportedHostKey> {
    content
        .lines()
        .filter_map(|line| parse_line(line, host, port))
        .collect()
}

fn parse_line(line: &str, host: &str, port: u16) -> Option<ImportedHostKey> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let patterns = fields.next()?;
    if patterns.starts_with('@') {
        // `@revoked` and `@cert-authority` (and any unknown marker) are never imported.
        return None;
    }
    let algorithm = fields.next()?;
    let blob_b64 = fields.next()?;
    if !host_matches(patterns, host, port) {
        return None;
    }
    let blob = STANDARD.decode(blob_b64).ok()?;
    if blob_key_type(&blob)? != algorithm.as_bytes() {
        return None;
    }
    let digest = digest::digest(&digest::SHA256, &blob);
    Some(ImportedHostKey {
        algorithm: algorithm.to_string(),
        fingerprint_sha256: format!("SHA256:{}", STANDARD_NO_PAD.encode(digest.as_ref())),
        public_key: format!("{algorithm} {blob_b64}"),
    })
}

/// The key type string at the start of an SSH wire-format public key blob.
fn blob_key_type(blob: &[u8]) -> Option<&[u8]> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    blob.get(4..4usize.checked_add(len)?)
}

/// The name OpenSSH writes and hashes for `host` on `port`.
fn host_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

fn host_matches(patterns: &str, host: &str, port: u16) -> bool {
    if let Some(hashed) = patterns.strip_prefix("|1|") {
        return hashed_matches(hashed, &host_name(host, port));
    }
    let mut matched = false;
    for pattern in patterns.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pattern),
        };
        if plain_matches(pattern, host, port) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

fn plain_matches(pattern: &str, host: &str, port: u16) -> bool {
    if let Some(rest) = pattern.strip_prefix('[') {
        let Some((name, port_str)) = rest.split_once("]:") else {
            return false;
        };
        return port_str.parse::<u16>().ok() == Some(port) && name.eq_ignore_ascii_case(host);
    }
    port == 22 && pattern.eq_ignore_ascii_case(host)
}

/// `hashed` is `<base64-salt>|<base64-hmac-sha1>` (the part after `|1|`).
fn hashed_matches(hashed: &str, name: &str) -> bool {
    let Some((salt, mac)) = hashed.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(mac)) = (STANDARD.decode(salt), STANDARD.decode(mac)) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    hmac::verify(&key, name.as_bytes(), &mac).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with `ssh-keygen -t ed25519`; fingerprint from `ssh-keygen -l`.
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMAKvbC1OkNvrNiAjJ6wli5nNQS5707OnbcrowxpV2Q";
    const FP: &str = "SHA256:9I6JDw93SZWDRe51mShFze57vAaKMdUWr3LkP0+FEEM";
    // `ssh-keygen -H` of `example.com <KEY>` and `[example.com]:2222 <KEY>`.
    const HASHED_22: &str = "|1|P/k1CxSv4YGoqUDOlqdNkrBY8L4=|RBraJUa1OYhkRqoJgqCS5mwsc94=";
    const HASHED_2222: &str = "|1|ADZ3S+V7TvI6gg4Ui8At5AZEAUA=|ASVT9SlOJjHE+eKmxAyEo1RZyYg=";

    fn parse(content: &str, host: &str, port: u16) -> Vec<ImportedHostKey> {
        parse_openssh_known_hosts_for_host(content, host, port)
    }

    #[test]
    fn plain_host_matches_port_22_with_fingerprint() {
        let keys = parse(&format!("example.com {KEY} a comment\n"), "example.com", 22);
        assert_eq!(
            keys,
            vec![ImportedHostKey {
                algorithm: "ssh-ed25519".into(),
                fingerprint_sha256: FP.into(),
                public_key: KEY.into(),
            }]
        );
        assert!(parse(&format!("example.com {KEY}"), "example.com", 2222).is_empty());
        assert!(parse(&format!("other.com {KEY}"), "example.com", 22).is_empty());
    }

    #[test]
    fn plain_host_is_case_insensitive() {
        assert_eq!(parse(&format!("Example.COM {KEY}"), "example.com", 22).len(), 1);
    }

    #[test]
    fn bracketed_host_matches_exact_port() {
        let content = format!("[example.com]:2222 {KEY}");
        assert_eq!(parse(&content, "example.com", 2222).len(), 1);
        assert!(parse(&content, "example.com", 22).is_empty());
        assert!(parse(&content, "example.com", 2223).is_empty());
        assert_eq!(parse(&format!("[example.com]:22 {KEY}"), "example.com", 22).len(), 1);
    }

    #[test]
    fn comma_list_matches_any_pattern() {
        let content = format!("a.com,example.com,[b.com]:2200,10.0.0.1 {KEY}");
        assert_eq!(parse(&content, "example.com", 22).len(), 1);
        assert_eq!(parse(&content, "10.0.0.1", 22).len(), 1);
        assert_eq!(parse(&content, "b.com", 2200).len(), 1);
        assert!(parse(&content, "c.com", 22).is_empty());
    }

    #[test]
    fn negation_excludes_the_line() {
        let content = format!("example.com,!example.com {KEY}");
        assert!(parse(&content, "example.com", 22).is_empty());
        let content = format!("!other.com,example.com {KEY}");
        assert_eq!(parse(&content, "example.com", 22).len(), 1);
        // A negation alone never matches.
        assert!(parse(&format!("!other.com {KEY}"), "example.com", 22).is_empty());
    }

    #[test]
    fn hashed_entries_match_host_and_port() {
        let content = format!("{HASHED_22} {KEY}\n{HASHED_2222} {KEY}\n");
        let k22 = parse(&content, "example.com", 22);
        assert_eq!(k22.len(), 1);
        assert_eq!(k22[0].fingerprint_sha256, FP);
        assert_eq!(parse(&content, "example.com", 2222).len(), 1);
        assert!(parse(&content, "example.com", 2223).is_empty());
        assert!(parse(&content, "other.com", 22).is_empty());
    }

    #[test]
    fn malformed_hashed_entries_are_skipped() {
        for bad in ["|1|", "|1|nosep", "|1|!!!|RBraJUa1OYhkRqoJgqCS5mwsc94=", "|1|P/k1CxSv4YGoqUDOlqdNkrBY8L4=|!!!"] {
            assert!(parse(&format!("{bad} {KEY}"), "example.com", 22).is_empty(), "{bad}");
        }
    }

    #[test]
    fn markers_comments_and_blank_lines_are_skipped() {
        let content = format!(
            "# example.com {KEY}\n\n   \n@revoked example.com {KEY}\n@cert-authority example.com {KEY}\n  example.com {KEY}  \n"
        );
        assert_eq!(parse(&content, "example.com", 22).len(), 1);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let content = "example.com\n\
            example.com ssh-ed25519\n\
            example.com ssh-ed25519 not*base64\n\
            example.com ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIIMAKvbC1OkNvrNiAjJ6wli5nNQS5707OnbcrowxpV2Q\n\
            example.com ssh-ed25519 AAAA\n\
            [example.com:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMAKvbC1OkNvrNiAjJ6wli5nNQS5707OnbcrowxpV2Q\n";
        assert!(parse(content, "example.com", 22).is_empty());
        assert!(parse(content, "example.com", 2222).is_empty());
    }

    #[test]
    fn returns_all_matches_in_file_order() {
        let ecdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFpdaIz843WyahYILA4owyhMrrYDqH6DTrK7M3QvEQx5LxubITv7v5Ta32tWqySxgJVGMA/JYcwx8vHfuv4NULs=";
        let keys = parse(&format!("example.com {ecdsa}\nexample.com {KEY}\n"), "example.com", 22);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].algorithm, "ecdsa-sha2-nistp256");
        assert_eq!(keys[1].algorithm, "ssh-ed25519");
    }

    #[test]
    fn sha256_fingerprint_is_unpadded_standard_base64() {
        let keys = parse(&format!("example.com {KEY}"), "example.com", 22);
        let fp = &keys[0].fingerprint_sha256;
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.ends_with('='));
        assert_eq!(fp.len(), "SHA256:".len() + 43);
    }
}
