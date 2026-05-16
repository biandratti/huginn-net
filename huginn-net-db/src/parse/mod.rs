//! Parser for the p0f `*.fp` database format.
//!
//! The entry points are the `FromStr` impls on [`crate::database::Database`],
//! [`crate::database::TcpDatabase`] and [`crate::database::HttpDatabase`].
//!
//! Internals are split by responsibility (all submodules are private):
//! - `common`: parsers and macros shared by both branches (label/type,
//!   classes, module headers, the `impl_from_str!` / `str_parser!` macros).
//! - `tcp`: TCP-specific leaf parsers and `parse_*_str` helpers
//!   (gated by `feature = "tcp"`).
//! - `http`: HTTP-specific leaf parsers, the `ua_os` table, and
//!   `parse_*_str` helpers (gated by `feature = "http"`).
//!
//! This module ties everything together by walking the line-oriented input,
//! tracking the current `[module:direction]` section, and dispatching to the
//! protocol-specific parsers.

mod common;

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "tcp")]
mod tcp;

#[cfg(feature = "tcp")]
pub use tcp::{
    parse_ip_version_str, parse_payload_size_str, parse_quirk_str, parse_tcp_option_str,
    parse_ttl_str, parse_window_size_str,
};

#[cfg(feature = "http")]
pub use http::{parse_http_header_str, parse_http_version_str};

#[cfg(all(feature = "tcp", feature = "http"))]
use crate::database::Database;
#[cfg(any(feature = "tcp", feature = "http"))]
use crate::database::FingerprintCollection;
#[cfg(feature = "http")]
use crate::database::HttpDatabase;
#[cfg(any(feature = "tcp", feature = "http"))]
use crate::database::Label;
#[cfg(feature = "tcp")]
use crate::database::TcpDatabase;
#[cfg(any(feature = "tcp", feature = "http"))]
use crate::error::DatabaseError;
#[cfg(feature = "http")]
use crate::http::Signature as HttpSignature;
#[cfg(feature = "tcp")]
use crate::tcp::Signature as TcpSignature;
#[cfg(any(feature = "tcp", feature = "http"))]
use std::str::FromStr;
#[cfg(any(feature = "tcp", feature = "http"))]
use tracing::{trace, warn};

/// Intermediate output of [`parse_sections`]: raw section content extracted
/// from a `p0f.fp`-formatted input. Per-protocol fields are gated by their
/// crate feature.
#[cfg(any(feature = "tcp", feature = "http"))]
#[derive(Default)]
struct ParsedSections {
    classes: Vec<String>,
    #[cfg(feature = "tcp")]
    mtu: Vec<(String, Vec<u16>)>,
    #[cfg(feature = "http")]
    ua_os: Vec<(String, Option<String>)>,
    #[cfg(feature = "tcp")]
    tcp_request: Vec<(Label, Vec<TcpSignature>)>,
    #[cfg(feature = "tcp")]
    tcp_response: Vec<(Label, Vec<TcpSignature>)>,
    #[cfg(feature = "http")]
    http_request: Vec<(Label, Vec<HttpSignature>)>,
    #[cfg(feature = "http")]
    http_response: Vec<(Label, Vec<HttpSignature>)>,
}

/// Parses a `p0f.fp`-formatted string into [`ParsedSections`]. Sections whose
/// crate feature is disabled are silently skipped (their `[label] = …` and
/// `sig = …` lines log a `warn!` and don't contribute to the output).
#[cfg(any(feature = "tcp", feature = "http"))]
fn parse_sections(s: &str) -> Result<ParsedSections, DatabaseError> {
    let mut out = ParsedSections::default();
    let mut cur_mod: Option<(String, Option<String>)> = None;

    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        if line.starts_with("classes") {
            out.classes.append(
                &mut common::parse_classes(line)
                    .map_err(|err| {
                        DatabaseError::Parse(format!("fail to parse `classes`: {line}, {err}"))
                    })?
                    .1,
            );
            continue;
        }

        #[cfg(feature = "http")]
        if line.starts_with("ua_os") {
            out.ua_os.append(
                &mut http::parse_ua_os(line)
                    .map_err(|err| {
                        DatabaseError::Parse(format!("fail to parse `ua_os`: {line}, {err}"))
                    })?
                    .1,
            );
            continue;
        }
        #[cfg(not(feature = "http"))]
        if line.starts_with("ua_os") {
            // `http` feature disabled: drop UA→OS table silently.
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            cur_mod = Some(
                common::parse_module(line)
                    .map_err(|err| {
                        DatabaseError::Parse(format!("fail to parse `module`: {line}, {err}"))
                    })?
                    .1,
            );
            continue;
        }

        let Some((module, direction)) = cur_mod.as_ref() else {
            return Err(DatabaseError::Parse(format!(
                "unexpected line outside the module: {line}"
            )));
        };

        let (_, (name, value)) = common::parse_named_value(line).map_err(|err| {
            DatabaseError::Parse(format!("fail to parse named value: {line}, {err}"))
        })?;

        match name {
            "label" if module == "mtu" => {
                #[cfg(feature = "tcp")]
                out.mtu.push((value.to_string(), vec![]));
            }
            "sig" if module == "mtu" => {
                #[cfg(feature = "tcp")]
                {
                    if let Some((_label, values)) = out.mtu.last_mut() {
                        let sig = value.parse::<u16>().map_err(|err| {
                            DatabaseError::Parse(format!(
                                "fail to parse `mtu` value: {value}, {err}"
                            ))
                        })?;
                        values.push(sig);
                    } else {
                        return Err(DatabaseError::Parse(format!(
                            "`mtu` value without `label`: {value}"
                        )));
                    }
                }
            }
            "label" => {
                let label = Label::from_str(value).map_err(|err| {
                    DatabaseError::Parse(format!("fail to parse `label`: {value}, {err}"))
                })?;
                match (module.as_str(), direction.as_deref()) {
                    #[cfg(feature = "tcp")]
                    ("tcp", Some("request")) => out.tcp_request.push((label, vec![])),
                    #[cfg(feature = "tcp")]
                    ("tcp", Some("response")) => out.tcp_response.push((label, vec![])),
                    #[cfg(feature = "http")]
                    ("http", Some("request")) => out.http_request.push((label, vec![])),
                    #[cfg(feature = "http")]
                    ("http", Some("response")) => out.http_response.push((label, vec![])),
                    _ => {
                        warn!("skip `label` in unknown module `{}`: {}", module, value);
                    }
                }
            }
            "sig" => match (module.as_str(), direction.as_deref()) {
                #[cfg(feature = "tcp")]
                ("tcp", Some("request")) => {
                    if let Some((label, values)) = out.tcp_request.last_mut() {
                        let sig: TcpSignature = value.parse()?;
                        trace!("sig for `{}` tcp request: {}", label, sig);
                        values.push(sig);
                    } else {
                        return Err(DatabaseError::Parse(format!(
                            "tcp signature without `label`: {value}"
                        )));
                    }
                }
                #[cfg(feature = "tcp")]
                ("tcp", Some("response")) => {
                    if let Some((label, values)) = out.tcp_response.last_mut() {
                        let sig: TcpSignature = value.parse()?;
                        trace!("sig for `{}` tcp response: {}", label, sig);
                        values.push(sig);
                    } else {
                        return Err(DatabaseError::Parse(format!(
                            "tcp signature without `label`: {value}"
                        )));
                    }
                }
                #[cfg(feature = "http")]
                ("http", Some("request")) => {
                    if let Some((label, values)) = out.http_request.last_mut() {
                        let sig: HttpSignature = value.parse()?;
                        trace!("sig for `{}` http request: {}", label, sig);
                        values.push(sig);
                    } else {
                        return Err(DatabaseError::Parse(format!(
                            "http signature without `label`: {value}"
                        )));
                    }
                }
                #[cfg(feature = "http")]
                ("http", Some("response")) => {
                    if let Some((label, values)) = out.http_response.last_mut() {
                        let sig: HttpSignature = value.parse()?;
                        trace!("sig for `{}` http response: {}", label, sig);
                        values.push(sig);
                    } else {
                        return Err(DatabaseError::Parse(format!(
                            "http signature without `label`: {value}"
                        )));
                    }
                }
                _ => {
                    warn!("skip `sig` in unknown module `{}`: {}", module, value);
                }
            },
            "sys" if module != "mtu" => {}
            _ => {
                warn!("skip unknown named value: {} = {}", name, value);
            }
        }
    }

    Ok(out)
}

#[cfg(all(feature = "tcp", feature = "http"))]
impl FromStr for Database {
    type Err = DatabaseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let out = parse_sections(s)?;
        let tcp = TcpDatabase {
            classes: out.classes.clone(),
            mtu: out.mtu,
            tcp_request: FingerprintCollection::new(out.tcp_request),
            tcp_response: FingerprintCollection::new(out.tcp_response),
        };
        let http = HttpDatabase {
            classes: out.classes,
            ua_os: out.ua_os,
            http_request: FingerprintCollection::new(out.http_request),
            http_response: FingerprintCollection::new(out.http_response),
        };
        Ok(Database { tcp, http })
    }
}

#[cfg(feature = "tcp")]
impl FromStr for TcpDatabase {
    type Err = DatabaseError;

    /// Parse a `p0f.fp`-formatted string and keep only the TCP-relevant
    /// sections (`classes`, `[mtu]`, `[tcp:request]`, `[tcp:response]`).
    /// HTTP-related sections present in the input are silently ignored.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let out = parse_sections(s)?;
        Ok(TcpDatabase {
            classes: out.classes,
            mtu: out.mtu,
            tcp_request: FingerprintCollection::new(out.tcp_request),
            tcp_response: FingerprintCollection::new(out.tcp_response),
        })
    }
}

#[cfg(feature = "http")]
impl FromStr for HttpDatabase {
    type Err = DatabaseError;

    /// Parse a `p0f.fp`-formatted string keeping only the HTTP-relevant
    /// sections (`classes`, `ua_os`, `[http:request]`, `[http:response]`).
    /// TCP-related sections present in the input are silently ignored.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let out = parse_sections(s)?;
        Ok(HttpDatabase {
            classes: out.classes,
            ua_os: out.ua_os,
            http_request: FingerprintCollection::new(out.http_request),
            http_response: FingerprintCollection::new(out.http_response),
        })
    }
}
