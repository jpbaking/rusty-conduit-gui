//! `conduit-core` — AirSwitch / ZeroOmega / SwitchyOmega `.bak` import into a v2 [`Proxy`].
//!
//! A `.bak` file is the options object the browser extension exports: every key that starts
//! with `+` is a profile (`"+Work Proxy": { "profileType": "FixedProfile", ... }`), and
//! `-startupProfileName` names the profile that was active. Older backups are base64-encoded
//! JSON; both forms are accepted.
//!
//! - `FixedProfile` becomes an [`UpstreamProfile`] (`http`, `https`, `socks5`, `socks4`/`socks4a`)
//!   with its color, username, and `bypassList`. Per-scheme servers (`proxyForHttp` /
//!   `proxyForHttps`) become a `composite` profile over per-scheme sub-profiles.
//! - One `SwitchProfile` becomes the Proxy's [`RoutingTablesConfig`]: `defaultProfileName` is the
//!   default target and each rule's condition is mapped onto a [`RoutingRule`]. The built-in
//!   `direct` stays `direct`; `system` becomes `direct` with a warning.
//! - Browser-only items (`PacProfile`, rule lists, `VirtualProfile`, other SwitchProfiles,
//!   unsupported condition types) are skipped and listed in [`AirSwitchImport::warnings`].
//!   Nothing is dropped silently.
//!
//! Passwords are never stored in the [`Proxy`]: each non-empty password is moved into an
//! [`ExtractedSecret`] (zeroized on drop) and the profile's `password` is left `None`. The caller
//! stores the secret in the Vault and attaches an `UpstreamPasswordSource::Vault` reference.

use std::collections::BTreeSet;
use std::fmt;

use base64::Engine;
use serde_json::{Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::v2_model::{
    Proxy, RouteHostLevels, RouteOneOrMany, RoutingRule, RoutingTablesConfig, UpstreamKind,
    UpstreamProfile,
};

/// The built-in `direct` profile name.
const DIRECT: &str = "direct";
/// The built-in `block` profile name.
const BLOCK: &str = "block";
/// Proxy name used when the backup gives none.
const DEFAULT_PROXY_NAME: &str = "AirSwitch import";

/// A password taken out of an imported file. It is never written into the [`Proxy`]; the caller
/// stores it in the Vault for the named profile. The value is zeroized on drop and redacted in
/// `Debug` output.
#[derive(Clone)]
pub struct ExtractedSecret {
    /// The [`UpstreamProfile::name`] the password belongs to.
    pub profile_name: String,
    pub password: Zeroizing<String>,
}

impl fmt::Debug for ExtractedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractedSecret")
            .field("profile_name", &self.profile_name)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Errors that stop an AirSwitch import. Everything else is a warning.
#[derive(Debug, Error)]
pub enum ImportError {
    #[error("not an AirSwitch backup: {0}")]
    Parse(String),
    #[error("not an AirSwitch backup: the top-level JSON value must be an object")]
    NotObject,
    #[error("not an AirSwitch backup: it contains no profiles (keys starting with `+`)")]
    NoProfiles,
    #[error("SwitchProfile {name:?} not found; available SwitchProfiles: {}", list(.available))]
    ProfileNotFound { name: String, available: Vec<String> },
    #[error(
        "profile {name:?} is a {kind}, not a SwitchProfile; available SwitchProfiles: {}",
        list(.available)
    )]
    NotSwitchProfile { name: String, kind: String, available: Vec<String> },
    #[error(
        "the backup has several SwitchProfiles and none is the startup profile; choose one: {}",
        list(.available)
    )]
    AmbiguousSwitch { available: Vec<String> },
}

fn list(names: &[String]) -> String {
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.iter().map(|n| format!("{n:?}")).collect::<Vec<_>>().join(", ")
    }
}

/// The result of [`import_airswitch_bak`].
#[derive(Debug, Clone)]
pub struct AirSwitchImport {
    /// The imported Proxy. Its profiles carry no passwords; see `extracted_secrets`.
    pub proxy: Proxy,
    /// Passwords found in the backup, one per profile, for the Vault.
    pub extracted_secrets: Vec<ExtractedSecret>,
    /// Everything that was skipped or changed, in plain words.
    pub warnings: Vec<String>,
    /// Number of upstream profiles in `proxy`.
    pub profile_count: usize,
    /// Number of routing rules in `proxy`.
    pub rule_count: usize,
}

/// Import an AirSwitch / ZeroOmega / SwitchyOmega `.bak` backup (JSON or base64 JSON).
///
/// `name` selects the `SwitchProfile` to import as the routing table. Without it, the startup
/// profile is used when it is a SwitchProfile, or the only SwitchProfile when there is exactly
/// one. The Proxy is named after the imported SwitchProfile.
pub fn import_airswitch_bak(json: &str, name: Option<&str>) -> Result<AirSwitchImport, ImportError> {
    let options = parse_options(json)?;
    Converter::default().run(&options, name)
}

/// Parse the `.bak` text (JSON, or base64-encoded JSON) into the options object.
fn parse_options(text: &str) -> Result<Map<String, Value>, ImportError> {
    let text = text.trim().trim_start_matches('\u{feff}').trim();
    let value: Value = if text.starts_with('{') {
        serde_json::from_str(text).map_err(|e| ImportError::Parse(format!("invalid JSON: {e}")))?
    } else {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|_| ImportError::Parse("neither JSON nor base64-encoded JSON".into()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| ImportError::Parse(format!("invalid base64-encoded JSON: {e}")))?
    };
    match value {
        Value::Object(m) => Ok(m),
        _ => Err(ImportError::NotObject),
    }
}

/// Deterministic profile name: lowercase ASCII alphanumerics joined by `_`
/// (`"Work Proxy"` → `work_proxy`). Names with no ASCII alphanumerics become `profile`.
pub(crate) fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if sep && !out.is_empty() {
                out.push('_');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        } else {
            sep = true;
        }
    }
    if out.is_empty() {
        "profile".to_string()
    } else {
        out
    }
}

fn str_field<'v>(v: &'v Value, key: &str) -> Option<&'v str> {
    v.get(key).and_then(Value::as_str)
}

fn int_field(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|n| {
        n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).or_else(|| n.as_str()?.trim().parse().ok())
    })
}

/// What a FixedProfile's server is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Server {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Default)]
struct Converter {
    used_names: BTreeSet<String>,
    profiles: Vec<UpstreamProfile>,
    secrets: Vec<ExtractedSecret>,
    warnings: Vec<String>,
}

impl Converter {
    fn warn(&mut self, w: impl Into<String>) {
        let w = w.into();
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }

    /// A unique profile name for `base`, never `direct` or `block`.
    fn alloc(&mut self, base: &str) -> String {
        let base = slugify(base);
        let mut candidate = base.clone();
        let mut n = 2;
        while candidate == DIRECT || candidate == BLOCK || self.used_names.contains(&candidate) {
            candidate = format!("{base}_{n}");
            n += 1;
        }
        self.used_names.insert(candidate.clone());
        candidate
    }

    fn run(
        mut self,
        options: &Map<String, Value>,
        selected: Option<&str>,
    ) -> Result<AirSwitchImport, ImportError> {
        // (AirSwitch name, profileType, value), sorted by name.
        let mut entries: Vec<(String, String, &Value)> = options
            .iter()
            .filter_map(|(k, v)| {
                let name = k.strip_prefix('+')?;
                let ty = str_field(v, "profileType").unwrap_or("").to_string();
                Some((name.to_string(), ty, v))
            })
            .collect();
        if entries.is_empty() {
            return Err(ImportError::NoProfiles);
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let switches: Vec<String> = entries
            .iter()
            .filter(|(_, ty, _)| ty == "SwitchProfile")
            .map(|(n, _, _)| n.clone())
            .collect();
        let startup = options
            .get("-startupProfileName")
            .and_then(Value::as_str)
            .map(str::to_string);

        let switch = match selected {
            Some(name) => match entries.iter().find(|(n, _, _)| n == name) {
                None => {
                    return Err(ImportError::ProfileNotFound {
                        name: name.to_string(),
                        available: switches,
                    })
                }
                Some((_, ty, _)) if ty != "SwitchProfile" => {
                    return Err(ImportError::NotSwitchProfile {
                        name: name.to_string(),
                        kind: if ty.is_empty() { "profile".into() } else { ty.clone() },
                        available: switches,
                    })
                }
                Some((n, _, _)) => Some(n.clone()),
            },
            None => match startup.as_ref().filter(|s| switches.contains(s)) {
                Some(s) => Some(s.clone()),
                None => match switches.len() {
                    0 => None,
                    1 => Some(switches[0].clone()),
                    _ => return Err(ImportError::AmbiguousSwitch { available: switches }),
                },
            },
        };

        // Fixed profiles first, so rules can name them. AirSwitch name -> profile name.
        let mut targets: Vec<(String, String)> = Vec::new();
        for (name, ty, v) in &entries {
            if ty == "FixedProfile" {
                if let Some(target) = self.convert_fixed(name, v) {
                    targets.push((name.clone(), target));
                }
            }
        }

        for (name, ty, _) in &entries {
            let reason = match ty.as_str() {
                "FixedProfile" => continue,
                "SwitchProfile" if Some(name) == switch.as_ref() => continue,
                "SwitchProfile" => "only one SwitchProfile is imported per Proxy".to_string(),
                "PacProfile" | "AutoDetectProfile" => {
                    "PAC scripts run in the browser only".to_string()
                }
                "RuleListProfile" | "SwitchyRuleListProfile" | "AutoProxyRuleListProfile" => {
                    "rule-list profiles are browser-only".to_string()
                }
                "VirtualProfile" => "virtual profiles are browser-only".to_string(),
                "DirectProfile" => "use the built-in `direct` profile".to_string(),
                "SystemProfile" => "the system proxy setting has no equivalent".to_string(),
                "" => "it has no profileType".to_string(),
                other => format!("profile type {other} is not supported"),
            };
            self.warn(format!("profile {name:?} ({ty}) skipped: {reason}"));
        }

        let mut proxy = Proxy::default();
        match &switch {
            Some(switch_name) => {
                let v = entries.iter().find(|(n, _, _)| n == switch_name).map(|e| e.2).unwrap();
                proxy.name = switch_name.clone();
                proxy.routing = self.convert_switch(switch_name, v, &targets);
            }
            None => {
                proxy.name = DEFAULT_PROXY_NAME.to_string();
                if let Some(start) = &startup {
                    if let Some((_, target)) = targets.iter().find(|(n, _)| n == start) {
                        proxy.name = start.clone();
                        proxy.routing.default = RouteOneOrMany::One(target.clone());
                    }
                }
                self.warn(
                    "the backup has no SwitchProfile: no routing rules imported; all traffic \
                     uses the default target",
                );
            }
        }

        proxy.profiles = self.profiles;
        Ok(AirSwitchImport {
            profile_count: proxy.profiles.len(),
            rule_count: proxy.routing.rules.len(),
            proxy,
            extracted_secrets: self.secrets,
            warnings: self.warnings,
        })
    }

    // -- FixedProfile ---------------------------------------------------------------------

    fn server_of(&mut self, profile: &str, v: &Value, prop: &str) -> Option<Server> {
        let p = v.get(prop)?;
        if p.is_null() {
            return None;
        }
        let host = str_field(p, "host").map(str::trim).unwrap_or("");
        let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        let port = int_field(p, "port").and_then(|n| u16::try_from(n).ok());
        match (host.is_empty(), port) {
            (false, Some(port)) if port > 0 => Some(Server {
                scheme: str_field(p, "scheme").unwrap_or("http").to_ascii_lowercase(),
                host: host.to_string(),
                port,
            }),
            _ => {
                self.warn(format!("profile {profile:?}: {prop} has no valid host/port; ignored"));
                None
            }
        }
    }

    /// Build one server profile named `key`, moving its password into `self.secrets`.
    fn server_profile(
        &mut self,
        profile: &str,
        v: &Value,
        server: &Server,
        auth_prop: &str,
        key: &str,
    ) -> Option<UpstreamProfile> {
        let kind = match server.scheme.as_str() {
            "http" => UpstreamKind::Http,
            "https" => UpstreamKind::Https { tls_insecure_skip_verify: false },
            "socks5" => UpstreamKind::Socks5,
            "socks4" | "socks4a" => {
                if server.scheme == "socks4" {
                    self.warn(format!(
                        "profile {profile:?}: SOCKS4 proxy imported as socks4a (remote DNS); the \
                         upstream server must support SOCKS4a"
                    ));
                }
                UpstreamKind::Socks4a
            }
            other => {
                self.warn(format!(
                    "profile {profile:?}: unsupported proxy scheme {other:?}; {auth_prop} skipped"
                ));
                return None;
            }
        };
        let mut out = UpstreamProfile {
            name: key.to_string(),
            kind,
            host: Some(server.host.clone()),
            port: Some(server.port),
            username: None,
            password: None,
            bypass: Vec::new(),
            color: None,
        };
        let auth = v.get("auth");
        let creds = auth
            .and_then(|a| a.get(auth_prop))
            .filter(|c| c.is_object())
            .or_else(|| auth.and_then(|a| a.get("all")).filter(|c| c.is_object()));
        if let Some(c) = creds {
            if let Some(user) = str_field(c, "username").filter(|u| !u.is_empty()) {
                out.username = Some(user.to_string());
            }
            if let Some(pass) = str_field(c, "password").filter(|p| !p.is_empty()) {
                self.secrets.push(ExtractedSecret {
                    profile_name: key.to_string(),
                    password: Zeroizing::new(pass.to_string()),
                });
                self.warn(format!(
                    "profile {profile:?}: password moved to the Vault for profile `{key}`"
                ));
            }
        }
        Some(out)
    }

    fn bypass_list(&mut self, name: &str, v: &Value) -> Vec<String> {
        let mut bypass = Vec::new();
        let Some(list) = v.get("bypassList").and_then(Value::as_array) else {
            return bypass;
        };
        for c in list {
            let pattern = str_field(c, "pattern").map(str::trim).unwrap_or("");
            let ty = str_field(c, "conditionType").unwrap_or("");
            if ty != "BypassCondition" || pattern.is_empty() {
                self.warn(format!(
                    "profile {name:?}: bypassList entry {ty:?} {pattern:?} is not a \
                     BypassCondition pattern; ignored"
                ));
                continue;
            }
            bypass.push(pattern.to_string());
        }
        bypass
    }

    /// Convert a FixedProfile, returning the profile name rules should target.
    fn convert_fixed(&mut self, name: &str, v: &Value) -> Option<String> {
        let fallback = self.server_of(name, v, "fallbackProxy");
        let http = self.server_of(name, v, "proxyForHttp");
        let https = self.server_of(name, v, "proxyForHttps");
        if v.get("proxyForFtp").is_some_and(|p| !p.is_null()) {
            self.warn(format!("profile {name:?}: proxyForFtp ignored (FTP is not proxied)"));
        }
        let bypass = self.bypass_list(name, v);
        let color = str_field(v, "color").filter(|c| !c.is_empty()).map(str::to_string);
        let per_http = http.filter(|p| Some(p) != fallback.as_ref());
        let per_https = https.filter(|p| Some(p) != fallback.as_ref());

        if per_http.is_none() && per_https.is_none() {
            let Some(server) = fallback else {
                self.warn(format!(
                    "profile {name:?} has no proxy server; rules that use it go `direct`"
                ));
                return Some(DIRECT.to_string());
            };
            let key = self.alloc(name);
            let mut profile = self.server_profile(name, v, &server, "fallbackProxy", &key)?;
            profile.bypass = bypass;
            profile.color = color;
            self.profiles.push(profile);
            return Some(key);
        }

        // Per-scheme servers: a composite over sub-profiles.
        let key = self.alloc(name);
        let mut parts: [String; 3] = Default::default();
        let mut subs = Vec::new();
        for (i, (part, server, prop)) in [
            ("http", per_http, "proxyForHttp"),
            ("https", per_https, "proxyForHttps"),
            ("fallback", fallback, "fallbackProxy"),
        ]
        .into_iter()
        .enumerate()
        {
            let Some(server) = server else {
                continue;
            };
            let sub_key = self.alloc(&format!("{key}_{part}"));
            if let Some(mut profile) = self.server_profile(name, v, &server, prop, &sub_key) {
                profile.color = color.clone();
                parts[i] = sub_key;
                subs.push(profile);
            }
        }
        if subs.is_empty() {
            self.warn(format!(
                "profile {name:?} has no usable proxy server; rules that use it go `direct`"
            ));
            return Some(DIRECT.to_string());
        }
        let [http, https, fallback] = parts;
        // An unset per-scheme part falls back to the fallback server (AirSwitch semantics).
        let pick = |s: String| if s.is_empty() { fallback.clone() } else { s };
        let composite = UpstreamProfile {
            name: key.clone(),
            kind: UpstreamKind::Composite { http: pick(http), https: pick(https), fallback: fallback.clone() },
            host: None,
            port: None,
            username: None,
            password: None,
            bypass,
            color,
        };
        self.profiles.push(composite);
        self.profiles.extend(subs);
        Some(key)
    }

    // -- SwitchProfile --------------------------------------------------------------------

    /// Resolve an AirSwitch profile name into a target, or `None` (with a warning) if it
    /// cannot be represented.
    fn resolve(&mut self, name: &str, targets: &[(String, String)], context: &str) -> Option<String> {
        match name {
            "direct" => return Some(DIRECT.to_string()),
            "system" => {
                self.warn(format!(
                    "{context}: the `system` profile has no equivalent; mapped to `direct`"
                ));
                return Some(DIRECT.to_string());
            }
            _ => {}
        }
        match targets.iter().find(|(n, _)| n == name) {
            Some((_, t)) => Some(t.clone()),
            None => {
                self.warn(format!(
                    "{context}: target profile {name:?} is not a FixedProfile that could be \
                     imported; skipped"
                ));
                None
            }
        }
    }

    fn convert_switch(
        &mut self,
        switch_name: &str,
        v: &Value,
        targets: &[(String, String)],
    ) -> RoutingTablesConfig {
        let mut routing = RoutingTablesConfig::default();
        let default_name = str_field(v, "defaultProfileName").unwrap_or("direct").to_string();
        let ctx = format!("SwitchProfile {switch_name:?} default");
        routing.default =
            RouteOneOrMany::One(self.resolve(&default_name, targets, &ctx).unwrap_or_else(|| {
                self.warn(format!("{ctx}: using `direct` instead"));
                DIRECT.to_string()
            }));

        let rules = v.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
        for (index, r) in rules.iter().enumerate() {
            let ctx = format!("SwitchProfile {switch_name:?} rule {}", index + 1);
            let Some(profile) = str_field(r, "profileName") else {
                self.warn(format!("{ctx}: no profileName; skipped"));
                continue;
            };
            let Some(target) = self.resolve(profile, targets, &ctx) else {
                continue;
            };
            let Some(cond) = r.get("condition") else {
                self.warn(format!("{ctx}: no condition; skipped"));
                continue;
            };
            match map_condition(cond, &mut self.warnings) {
                Ok(mut rule) => {
                    rule.target = RouteOneOrMany::One(target);
                    routing.rules.push(rule);
                }
                Err(reason) => self.warn(format!("{ctx}: {reason}; skipped")),
            }
        }
        routing
    }
}

fn split_pipes(p: &str) -> Vec<String> {
    p.split('|').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// Reject JavaScript regex features the Rust `regex` engine lacks.
fn check_regex(p: &str) -> Result<(), String> {
    if ["(?=", "(?!", "(?<=", "(?<!"].iter().any(|l| p.contains(l)) {
        return Err(format!("regex {p:?} uses lookarounds, which are not supported"));
    }
    Ok(())
}

const URL_RULE_NOTE: &str =
    "URL rule: matches only plain HTTP or MITM-decrypted HTTPS (never SOCKS or opaque CONNECT)";

const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// Map one AirSwitch condition object onto a rule (target still `direct`).
fn map_condition(c: &Value, warnings: &mut Vec<String>) -> Result<RoutingRule, String> {
    let mut note = |w: String| {
        if !warnings.contains(&w) {
            warnings.push(w);
        }
    };
    let ty = str_field(c, "conditionType").unwrap_or("");
    let pattern = || {
        str_field(c, "pattern")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("{ty} has no pattern"))
    };
    let mut r = RoutingRule::to_target(RouteOneOrMany::One(DIRECT.to_string()));
    match ty {
        "HostWildcardCondition" => {
            let parts = split_pipes(&pattern()?);
            if parts.is_empty() {
                return Err(format!("{ty} has no pattern"));
            }
            r.host_wildcard = Some(RouteOneOrMany::Many(parts));
        }
        "HostRegexCondition" => {
            let p = pattern()?;
            check_regex(&p)?;
            r.host_regex = Some(RouteOneOrMany::One(p));
        }
        "UrlWildcardCondition" => {
            let parts = split_pipes(&pattern()?);
            if parts.is_empty() {
                return Err(format!("{ty} has no pattern"));
            }
            r.url_wildcard = Some(RouteOneOrMany::Many(parts));
            note(URL_RULE_NOTE.to_string());
        }
        "UrlRegexCondition" => {
            let p = pattern()?;
            check_regex(&p)?;
            r.url_regex = Some(RouteOneOrMany::One(p));
            note(URL_RULE_NOTE.to_string());
        }
        "KeywordCondition" => {
            r.keyword = Some(RouteOneOrMany::Many(vec![pattern()?]));
            note(URL_RULE_NOTE.to_string());
        }
        "IpCondition" => {
            let ip = str_field(c, "ip").map(str::trim).unwrap_or("");
            let ip = ip.strip_prefix('[').and_then(|i| i.strip_suffix(']')).unwrap_or(ip);
            if ip.is_empty() {
                return Err(format!("{ty} has no ip"));
            }
            let cidr = match int_field(c, "prefixLength") {
                Some(p) => format!("{ip}/{p}"),
                None => ip.to_string(),
            };
            r.cidr = Some(RouteOneOrMany::Many(vec![cidr]));
        }
        "BypassCondition" => r.bypass = Some(RouteOneOrMany::Many(vec![pattern()?])),
        "HostLevelsCondition" => {
            let min = int_field(c, "minValue").unwrap_or(1).max(0);
            let max = int_field(c, "maxValue").unwrap_or(1).max(0);
            if min > max {
                r.disabled = true;
                note(format!("HostLevelsCondition {min}~{max} never matches; rule disabled"));
            } else {
                r.host_levels = Some(RouteHostLevels {
                    min: u32::try_from(min).ok(),
                    max: u32::try_from(max).ok(),
                });
            }
        }
        "WeekdayCondition" => {
            let mut sel = [false; 7];
            match str_field(c, "days").filter(|d| !d.is_empty()) {
                Some(days) => {
                    for (i, ch) in days.chars().take(7).enumerate() {
                        sel[i] = u32::from(ch) > 64;
                    }
                }
                None => {
                    let start = int_field(c, "startDay").unwrap_or(0);
                    let end = int_field(c, "endDay").unwrap_or(0);
                    for (i, s) in sel.iter_mut().enumerate() {
                        *s = (start..=end).contains(&(i as i64));
                    }
                }
            }
            let days: Vec<String> = WEEKDAYS
                .iter()
                .zip(sel)
                .filter(|(_, on)| *on)
                .map(|(d, _)| d.to_string())
                .collect();
            if days.is_empty() {
                r.disabled = true;
                note("WeekdayCondition selects no day; rule disabled".to_string());
            } else {
                r.weekday = Some(RouteOneOrMany::Many(days));
            }
        }
        "TimeCondition" => {
            let start = int_field(c, "startHour").unwrap_or(0);
            let end = int_field(c, "endHour").unwrap_or(0);
            let valid = |h: i64| (0..24).contains(&h);
            if !valid(start) || !valid(end) {
                return Err(format!("{ty} has invalid hours {start}~{end}"));
            }
            if start > end {
                r.disabled = true;
                note(format!("TimeCondition {start}~{end} never matches; rule disabled"));
            } else {
                r.time = Some(RouteOneOrMany::Many(vec![format!("{start:02}:00-{end:02}:59")]));
            }
        }
        "TrueCondition" => r.match_all = true,
        "FalseCondition" => {
            r.disabled = true;
            note("FalseCondition rule kept but disabled".to_string());
        }
        other => return Err(format!("unsupported conditionType {other:?}")),
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2_validate::validate_proxy;
    use serde_json::json;

    fn backup() -> String {
        json!({
            "-startupProfileName": "auto switch",
            "+Work Proxy": {
                "profileType": "FixedProfile",
                "name": "Work Proxy",
                "color": "#99ccee",
                "fallbackProxy": { "scheme": "http", "host": "proxy.corp.example", "port": 3128 },
                "auth": { "fallbackProxy": { "username": "alice", "password": "hunter2-secret" } },
                "bypassList": [
                    { "conditionType": "BypassCondition", "pattern": "<local>" },
                    { "conditionType": "BypassCondition", "pattern": "10.0.0.0/8" },
                    { "conditionType": "HostWildcardCondition", "pattern": "*.x" }
                ]
            },
            "+socks": {
                "profileType": "FixedProfile",
                "fallbackProxy": { "scheme": "socks4", "host": "127.0.0.1", "port": 1081 }
            },
            "+auto switch": {
                "profileType": "SwitchProfile",
                "defaultProfileName": "direct",
                "rules": [
                    { "condition": { "conditionType": "HostWildcardCondition", "pattern": "*.corp.example|intranet" }, "profileName": "Work Proxy" },
                    { "condition": { "conditionType": "HostRegexCondition", "pattern": "^db\\d+\\.corp$" }, "profileName": "Work Proxy" },
                    { "condition": { "conditionType": "UrlWildcardCondition", "pattern": "http://*/api/*" }, "profileName": "socks" },
                    { "condition": { "conditionType": "UrlRegexCondition", "pattern": "^https?://ads\\." }, "profileName": "direct" },
                    { "condition": { "conditionType": "KeywordCondition", "pattern": "tracker" }, "profileName": "direct" },
                    { "condition": { "conditionType": "IpCondition", "ip": "192.168.0.0", "prefixLength": 16 }, "profileName": "direct" },
                    { "condition": { "conditionType": "HostLevelsCondition", "minValue": 0, "maxValue": 0 }, "profileName": "direct" },
                    { "condition": { "conditionType": "BypassCondition", "pattern": "<local>" }, "profileName": "direct" },
                    { "condition": { "conditionType": "TimeCondition", "startHour": 9, "endHour": 17 }, "profileName": "Work Proxy" },
                    { "condition": { "conditionType": "WeekdayCondition", "startDay": 1, "endDay": 5 }, "profileName": "Work Proxy" },
                    { "condition": { "conditionType": "HostWildcardCondition", "pattern": "*.sys" }, "profileName": "system" },
                    { "condition": { "conditionType": "FancyCondition", "pattern": "x" }, "profileName": "direct" },
                    { "condition": { "conditionType": "HostWildcardCondition", "pattern": "*.pac" }, "profileName": "my pac" }
                ]
            },
            "+my pac": { "profileType": "PacProfile", "pacUrl": "http://wpad/wpad.dat" },
            "+lists": { "profileType": "RuleListProfile" },
            "+virt": { "profileType": "VirtualProfile", "defaultProfileName": "socks" },
            "schemaVersion": 2
        })
        .to_string()
    }

    #[test]
    fn airswitch_imports_profiles_rules_and_extracts_passwords() {
        let out = import_airswitch_bak(&backup(), None).unwrap();
        let p = &out.proxy;
        assert_eq!(p.name, "auto switch");
        assert_eq!(out.profile_count, 2);
        let work = p.profiles.iter().find(|x| x.name == "work_proxy").unwrap();
        assert_eq!(work.kind, UpstreamKind::Http);
        assert_eq!(work.host.as_deref(), Some("proxy.corp.example"));
        assert_eq!(work.port, Some(3128));
        assert_eq!(work.username.as_deref(), Some("alice"));
        assert_eq!(work.password, None);
        assert_eq!(work.color.as_deref(), Some("#99ccee"));
        assert_eq!(work.bypass, vec!["<local>".to_string(), "10.0.0.0/8".to_string()]);
        let socks = p.profiles.iter().find(|x| x.name == "socks").unwrap();
        assert_eq!(socks.kind, UpstreamKind::Socks4a);

        assert_eq!(out.extracted_secrets.len(), 1);
        assert_eq!(out.extracted_secrets[0].profile_name, "work_proxy");
        assert_eq!(out.extracted_secrets[0].password.as_str(), "hunter2-secret");

        // 13 rules: system → direct (kept), Fancy and PAC target skipped.
        assert_eq!(out.rule_count, 11);
        let rules = &p.routing.rules;
        assert_eq!(
            rules[0].host_wildcard.as_ref().unwrap().as_slice(),
            ["*.corp.example".to_string(), "intranet".to_string()]
        );
        assert_eq!(rules[0].target.as_slice(), ["work_proxy".to_string()]);
        assert!(rules[1].host_regex.is_some());
        assert!(rules[2].url_wildcard.is_some());
        assert_eq!(rules[2].target.as_slice(), ["socks".to_string()]);
        assert!(rules[3].url_regex.is_some());
        assert!(rules[4].keyword.is_some());
        assert_eq!(rules[5].cidr.as_ref().unwrap().as_slice(), ["192.168.0.0/16".to_string()]);
        assert_eq!(rules[6].host_levels, Some(RouteHostLevels { min: Some(0), max: Some(0) }));
        assert!(rules[7].bypass.is_some());
        assert_eq!(rules[8].time.as_ref().unwrap().as_slice(), ["09:00-17:59".to_string()]);
        assert_eq!(rules[9].weekday.as_ref().unwrap().as_slice().len(), 5);
        assert_eq!(rules[10].target.as_slice(), ["direct".to_string()]);
        assert_eq!(p.routing.default.as_slice(), ["direct".to_string()]);

        validate_proxy(p, &[], &[]).unwrap();
    }

    #[test]
    fn airswitch_warns_about_everything_skipped() {
        let out = import_airswitch_bak(&backup(), None).unwrap();
        let all = out.warnings.join("\n");
        for needle in [
            "\"my pac\" (PacProfile) skipped",
            "\"lists\" (RuleListProfile) skipped",
            "\"virt\" (VirtualProfile) skipped",
            "`system` profile has no equivalent",
            "unsupported conditionType \"FancyCondition\"",
            "target profile \"my pac\"",
            "SOCKS4 proxy imported as socks4a",
            "bypassList entry \"HostWildcardCondition\"",
            "password moved to the Vault",
        ] {
            assert!(all.contains(needle), "missing warning {needle:?} in:\n{all}");
        }
    }

    #[test]
    fn airswitch_never_keeps_plaintext_passwords() {
        let out = import_airswitch_bak(&backup(), None).unwrap();
        let json = serde_json::to_string(&out.proxy).unwrap();
        assert!(!json.contains("hunter2-secret"));
        let debug = format!("{out:?}");
        assert!(!debug.contains("hunter2-secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn airswitch_per_scheme_servers_become_a_composite() {
        let bak = json!({
            "+split": {
                "profileType": "FixedProfile",
                "fallbackProxy": { "scheme": "socks5", "host": "s.example", "port": 1080 },
                "proxyForHttp": { "scheme": "http", "host": "h.example", "port": 8080 },
                "auth": { "proxyForHttp": { "username": "u", "password": "pw-http" } }
            },
            "-startupProfileName": "split"
        })
        .to_string();
        let out = import_airswitch_bak(&bak, None).unwrap();
        let p = &out.proxy;
        assert_eq!(p.name, "split");
        assert_eq!(p.routing.default.as_slice(), ["split".to_string()]);
        let composite = p.profiles.iter().find(|x| x.name == "split").unwrap();
        assert_eq!(
            composite.kind,
            UpstreamKind::Composite {
                http: "split_http".into(),
                https: "split_fallback".into(),
                fallback: "split_fallback".into()
            }
        );
        assert_eq!(out.extracted_secrets[0].profile_name, "split_http");
        assert!(out.warnings.iter().any(|w| w.contains("no SwitchProfile")));
        validate_proxy(p, &[], &[]).unwrap();
    }

    #[test]
    fn airswitch_accepts_base64_and_selects_switch_by_name() {
        let bak = json!({
            "+a": { "profileType": "SwitchProfile", "defaultProfileName": "direct", "rules": [] },
            "+b": { "profileType": "SwitchProfile", "defaultProfileName": "system", "rules": [] }
        })
        .to_string();
        assert!(matches!(
            import_airswitch_bak(&bak, None),
            Err(ImportError::AmbiguousSwitch { .. })
        ));
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bak);
        let out = import_airswitch_bak(&encoded, Some("b")).unwrap();
        assert_eq!(out.proxy.name, "b");
        assert!(out.warnings.iter().any(|w| w.contains("\"a\" (SwitchProfile) skipped")));
        assert!(matches!(
            import_airswitch_bak(&bak, Some("zzz")),
            Err(ImportError::ProfileNotFound { .. })
        ));
    }

    #[test]
    fn airswitch_rejects_non_backups() {
        assert!(matches!(import_airswitch_bak("{ nope", None), Err(ImportError::Parse(_))));
        assert!(matches!(import_airswitch_bak("[1]", None), Err(ImportError::Parse(_))));
        assert!(matches!(import_airswitch_bak("{\"x\":1}", None), Err(ImportError::NoProfiles)));
        let bak = json!({ "+f": { "profileType": "FixedProfile",
            "fallbackProxy": { "scheme": "http", "host": "h", "port": 1 } } })
        .to_string();
        assert!(matches!(
            import_airswitch_bak(&bak, Some("f")),
            Err(ImportError::NotSwitchProfile { .. })
        ));
    }

    #[test]
    fn airswitch_slug_names_avoid_builtins_and_collisions() {
        let bak = json!({
            "+Direct": { "profileType": "FixedProfile",
                "fallbackProxy": { "scheme": "http", "host": "a", "port": 1 } },
            "+direct!": { "profileType": "FixedProfile",
                "fallbackProxy": { "scheme": "https", "host": "b", "port": 2 } }
        })
        .to_string();
        let out = import_airswitch_bak(&bak, None).unwrap();
        let names: Vec<_> = out.proxy.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["direct_2", "direct_3"]);
        assert_eq!(slugify("Work Proxy"), "work_proxy");
        assert_eq!(slugify("!!"), "profile");
    }
}
