use std::str::FromStr;

#[cfg(all(feature = "tcp", feature = "http"))]
use crate::database::Database;
#[cfg(any(feature = "tcp", feature = "http"))]
use crate::database::FingerprintCollection;
#[cfg(feature = "http")]
use crate::database::HttpDatabase;
#[cfg(feature = "tcp")]
use crate::database::TcpDatabase;
use crate::database::{Label, Type};
use crate::error::DatabaseError;
#[cfg(feature = "http")]
use crate::http::{Header as HttpHeader, Signature as HttpSignature, Version as HttpVersion};
#[cfg(feature = "tcp")]
use crate::tcp::{
    IpVersion, PayloadSize, Quirk, Signature as TcpSignature, TcpOption, Ttl, WindowSize,
};
use nom::branch::alt;
use nom::bytes::complete::take_until;
#[cfg(feature = "http")]
use nom::bytes::complete::take_while;
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::character::complete::alpha1;
#[cfg(feature = "http")]
use nom::character::complete::char;
#[cfg(feature = "tcp")]
use nom::character::complete::digit1;
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::character::complete::{alphanumeric1, space0};
#[cfg(feature = "tcp")]
use nom::combinator::map_res;
use nom::combinator::{map, opt};
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::multi::separated_list0;
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::multi::separated_list1;
#[cfg(feature = "http")]
use nom::sequence::pair;
#[cfg(feature = "tcp")]
use nom::sequence::separated_pair;
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::sequence::terminated;
use nom::*;
use nom::{bytes::complete::tag, combinator::rest, sequence::preceded, IResult};
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
                &mut parse_classes(line)
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
                &mut parse_ua_os(line)
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
                parse_module(line)
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

        let (_, (name, value)) = parse_named_value(line).map_err(|err| {
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
                let (_, label) = parse_label(value).map_err(|err| {
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

macro_rules! impl_from_str {
    ($ty:ty, $parse:ident) => {
        impl FromStr for $ty {
            type Err = DatabaseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let (remaining, res) = $parse(s).map_err(|err| {
                    DatabaseError::Parse(format!(
                        "parse {} failed: {}, {}",
                        stringify!($ty),
                        s,
                        err
                    ))
                })?;

                if !remaining.is_empty() {
                    Err(DatabaseError::Parse(format!(
                        "parse {} failed, remaining: {}",
                        stringify!($ty),
                        remaining
                    )))
                } else {
                    Ok(res)
                }
            }
        }
    };
}

impl_from_str!(Label, parse_label);
impl_from_str!(Type, parse_type);
#[cfg(feature = "tcp")]
impl_from_str!(TcpSignature, parse_tcp_signature);
#[cfg(feature = "http")]
impl_from_str!(HttpSignature, parse_http_signature);

#[cfg(any(feature = "tcp", feature = "http"))]
macro_rules! str_parser {
    ($name:ident, $ty:ty, $parse:ident) => {
        pub fn $name(s: &str) -> Result<$ty, DatabaseError> {
            let (remaining, value) = $parse(s).map_err(|err| {
                DatabaseError::Parse(format!("parse {} failed: {}, {}", stringify!($ty), s, err))
            })?;
            if !remaining.is_empty() {
                Err(DatabaseError::Parse(format!(
                    "parse {} failed, remaining: {}",
                    stringify!($ty),
                    remaining
                )))
            } else {
                Ok(value)
            }
        }
    };
}

#[cfg(feature = "tcp")]
str_parser!(parse_ip_version_str, IpVersion, parse_ip_version);
#[cfg(feature = "tcp")]
str_parser!(parse_ttl_str, Ttl, parse_ttl);
#[cfg(feature = "tcp")]
str_parser!(parse_window_size_str, WindowSize, parse_window_size);
#[cfg(feature = "tcp")]
str_parser!(parse_tcp_option_str, TcpOption, parse_tcp_option);
#[cfg(feature = "tcp")]
str_parser!(parse_quirk_str, Quirk, parse_quirk);
#[cfg(feature = "tcp")]
str_parser!(parse_payload_size_str, PayloadSize, parse_payload_size);
#[cfg(feature = "http")]
str_parser!(parse_http_version_str, HttpVersion, parse_http_version);
#[cfg(feature = "http")]
str_parser!(parse_http_header_str, HttpHeader, parse_http_header);

#[cfg(any(feature = "tcp", feature = "http"))]
fn parse_named_value(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, (name, _, _, _, value)) =
        (alphanumeric1, space0, tag("="), space0, rest).parse(input)?;
    Ok((input, (name, value)))
}

#[cfg(any(feature = "tcp", feature = "http"))]
fn parse_classes(input: &str) -> IResult<&str, Vec<String>> {
    let (input, (_, _, _, _, classes)) = (
        tag("classes"),
        space0,
        tag("="),
        space0,
        separated_list0(tag(","), alphanumeric1),
    )
        .parse(input)?;

    let class_vec = classes.into_iter().map(|s| s.to_string()).collect();
    Ok((input, class_vec))
}

#[cfg(any(feature = "tcp", feature = "http"))]
fn parse_module(input: &str) -> IResult<&str, (String, Option<String>)> {
    let (input, (_, module, direction, _)) =
        (tag("["), alpha1, opt(preceded(tag(":"), alpha1)), tag("]")).parse(input)?;
    let module_str = module.to_string();
    let direction_str = direction.map(|s| s.to_string());

    Ok((input, (module_str, direction_str)))
}

#[cfg(feature = "http")]
fn parse_ua_os(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    let (input, (_, _, _, _, values)) = (
        tag("ua_os"),
        space0,
        tag("="),
        space0,
        separated_list0(tag(","), parse_key_value),
    )
        .parse(input)?;

    let result = values
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
        .collect();

    Ok((input, result))
}

#[cfg(feature = "http")]
fn parse_key_value(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let (input, (name, _, value)) =
        (alphanumeric1, space0, opt(preceded((space0, tag("="), space0), alphanumeric1)))
            .parse(input)?;

    Ok((input, (name, value)))
}

fn parse_label(input: &str) -> IResult<&str, Label> {
    let (input, (ty, _, class, _, name, flavor)) = (
        parse_type,
        tag(":"),
        alt((map(tag("!"), |_| None), map(take_until(":"), |s: &str| Some(s.to_string())))),
        tag(":"),
        take_until(":"),
        opt(preceded(tag(":"), rest)),
    )
        .parse(input)?;

    Ok((
        input,
        Label {
            ty,
            class,
            name: name.to_string(),
            flavor: flavor.filter(|f| !f.is_empty()).map(String::from),
        },
    ))
}

fn parse_type(input: &str) -> IResult<&str, Type> {
    alt((tag("s").map(|_| Type::Specified), tag("g").map(|_| Type::Generic))).parse(input)
}

#[cfg(feature = "tcp")]
fn parse_tcp_signature(input: &str) -> IResult<&str, TcpSignature> {
    let (
        input,
        (version, _, ittl, _, olen, _, mss, _, wsize, _, wscale, _, olayout, _, quirks, _, pclass),
    ) = (
        parse_ip_version,
        tag(":"),
        parse_ttl,
        tag(":"),
        map_res(digit1, |s: &str| s.parse::<u8>()), // olen
        tag(":"),
        alt((tag("*").map(|_| None), map_res(digit1, |s: &str| s.parse::<u16>().map(Some)))), // mss
        tag(":"),
        parse_window_size,
        tag(","),
        alt((tag("*").map(|_| None), map_res(digit1, |s: &str| s.parse::<u8>().map(Some)))), // wscale
        tag(":"),
        separated_list1(tag(","), parse_tcp_option),
        tag(":"),
        separated_list0(tag(","), parse_quirk),
        tag(":"),
        parse_payload_size,
    )
        .parse(input)?;

    Ok((
        input,
        TcpSignature { version, ittl, olen, mss, wsize, wscale, olayout, quirks, pclass },
    ))
}

#[cfg(feature = "tcp")]
fn parse_ip_version(input: &str) -> IResult<&str, IpVersion> {
    alt((
        map(tag("4"), |_| IpVersion::V4),
        map(tag("6"), |_| IpVersion::V6),
        map(tag("*"), |_| IpVersion::Any),
    ))
    .parse(input)
}

#[cfg(feature = "tcp")]
fn parse_ttl(input: &str) -> IResult<&str, Ttl> {
    alt((
        map_res(terminated(digit1, tag("-")), |s: &str| s.parse::<u8>().map(Ttl::Bad)),
        map_res(terminated(digit1, tag("+?")), |s: &str| s.parse::<u8>().map(Ttl::Guess)),
        map_res(
            separated_pair(digit1, tag("+"), digit1),
            |(ttl_str, distance_str): (&str, &str)| match (
                ttl_str.parse::<u8>(),
                distance_str.parse::<u8>(),
            ) {
                (Ok(ttl), Ok(distance)) => Ok(Ttl::Distance(ttl, distance)),
                (Err(_), _) => Err("Failed to parse ttl"),
                (_, Err(_)) => Err("Failed to parse distance"),
            },
        ),
        map_res(digit1, |s: &str| s.parse::<u8>().map(Ttl::Value)),
    ))
    .parse(input)
}

#[cfg(feature = "tcp")]
fn parse_window_size(input: &str) -> IResult<&str, WindowSize> {
    alt((
        map(tag("*"), |_| WindowSize::Any),
        map_res(preceded(tag("mss*"), digit1), |s: &str| s.parse::<u8>().map(WindowSize::Mss)),
        map_res(preceded(tag("mtu*"), digit1), |s: &str| s.parse::<u8>().map(WindowSize::Mtu)),
        map_res(preceded(tag("%"), digit1), |s: &str| s.parse::<u16>().map(WindowSize::Mod)),
        map_res(digit1, |s: &str| s.parse::<u16>().map(WindowSize::Value)),
    ))
    .parse(input)
}

#[cfg(feature = "tcp")]
fn parse_tcp_option(input: &str) -> IResult<&str, TcpOption> {
    alt((
        map_res(preceded(tag("eol+"), digit1), |s: &str| s.parse::<u8>().map(TcpOption::Eol)),
        tag("nop").map(|_| TcpOption::Nop),
        tag("mss").map(|_| TcpOption::Mss),
        tag("ws").map(|_| TcpOption::Ws),
        tag("sok").map(|_| TcpOption::Sok),
        tag("sack").map(|_| TcpOption::Sack),
        tag("ts").map(|_| TcpOption::TS),
        preceded(tag("?"), map(digit1, |s: &str| s.parse::<u8>().unwrap_or(0)))
            .map(TcpOption::Unknown),
    ))
    .parse(input)
}

#[cfg(feature = "tcp")]
fn parse_quirk(input: &str) -> IResult<&str, Quirk> {
    alt((
        map(tag("df"), |_| Quirk::Df),
        map(tag("id+"), |_| Quirk::NonZeroID),
        map(tag("id-"), |_| Quirk::ZeroID),
        map(tag("ecn"), |_| Quirk::Ecn),
        map(tag("0+"), |_| Quirk::MustBeZero),
        map(tag("flow"), |_| Quirk::FlowID),
        map(tag("seq-"), |_| Quirk::SeqNumZero),
        map(tag("ack+"), |_| Quirk::AckNumNonZero),
        map(tag("ack-"), |_| Quirk::AckNumZero),
        map(tag("uptr+"), |_| Quirk::NonZeroURG),
        map(tag("urgf+"), |_| Quirk::Urg),
        map(tag("pushf+"), |_| Quirk::Push),
        map(tag("ts1-"), |_| Quirk::OwnTimestampZero),
        map(tag("ts2+"), |_| Quirk::PeerTimestampNonZero),
        map(tag("opt+"), |_| Quirk::TrailinigNonZero),
        map(tag("exws"), |_| Quirk::ExcessiveWindowScaling),
        map(tag("bad"), |_| Quirk::OptBad),
    ))
    .parse(input)
}

#[cfg(feature = "tcp")]
fn parse_payload_size(input: &str) -> IResult<&str, PayloadSize> {
    alt((
        map(tag("0"), |_| PayloadSize::Zero),
        map(tag("+"), |_| PayloadSize::NonZero),
        map(tag("*"), |_| PayloadSize::Any),
    ))
    .parse(input)
}

#[cfg(feature = "http")]
fn parse_http_signature(input: &str) -> IResult<&str, HttpSignature> {
    let (input, (version, _, horder, _, habsent, _, expsw)) = (
        parse_http_version,
        tag(":"),
        separated_list1(tag(","), parse_http_header),
        tag(":"),
        opt(separated_list0(tag(","), parse_http_header)),
        tag(":"),
        rest,
    )
        .parse(input)?;

    let habsent = habsent
        .unwrap_or_default()
        .into_iter()
        .filter(|h| !h.name.is_empty())
        .collect();

    Ok((input, HttpSignature { version, horder, habsent, expsw: expsw.to_string() }))
}

#[cfg(feature = "http")]
fn parse_http_version(input: &str) -> IResult<&str, HttpVersion> {
    alt((
        map(tag("0"), |_| HttpVersion::V10),
        map(tag("1"), |_| HttpVersion::V11),
        map(tag("*"), |_| HttpVersion::Any),
    ))
    .parse(input)
}

#[cfg(feature = "http")]
fn parse_header_key_value(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    pair(
        take_while(|c: char| (c.is_ascii_alphanumeric() || c == '-') && c != ':' && c != '='),
        opt(preceded(tag("=["), terminated(take_until("]"), char(']')))),
    )
    .parse(input)
}

#[cfg(feature = "http")]
fn parse_http_header(input: &str) -> IResult<&str, HttpHeader> {
    let (input, optional) = opt(char('?')).parse(input)?;
    let (input, (name, value)) = parse_header_key_value(input)?;

    Ok((
        input,
        HttpHeader {
            optional: optional.is_some(),
            name: name.to_string(),
            value: value.map(|s| s.to_string()),
        },
    ))
}
