use std::str::FromStr;

use failure::{bail, format_err, Error};
use log::{trace, warn};
//use nom::types::CompleteStr;
use crate::db::{Label, Type};
use crate::{
    db::Database,
    http::{Header as HttpHeader, Signature as HttpSignature, Version as HttpVersion},
    tcp::{IpVersion, PayloadSize, Quirk, Signature as TcpSignature, TcpOption, Ttl, WindowSize},
};
use nom::branch::alt;
use nom::bytes::complete::take_while;
use nom::character::complete::{alpha1, digit1};
use nom::combinator::{map, map_res, opt};
use nom::multi::separated_list0;
use nom::sequence::{separated_pair, terminated};
use nom::*;
use nom::{
    bytes::complete::tag,
    character::complete::{alphanumeric1, space0},
    combinator::rest,
    sequence::{preceded, tuple},
    IResult,
};

impl FromStr for Database {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut classes = vec![];
        let mut mtu = vec![];
        let mut ua_os = vec![];
        let mut tcp_request = vec![];
        let mut tcp_response = vec![];
        let mut http_request = vec![];
        let mut http_response = vec![];
        let mut cur_mod = None;

        for line in s.lines() {
            let line = CompleteStr(line.trim());

            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            if line.starts_with("classes") {
                classes.append(
                    &mut parse_classes(line)
                        .map_err(|err| format_err!("fail to parse `classes`: {}, {}", line, err))?
                        .1,
                );
            } else if line.starts_with("ua_os") {
                ua_os.append(
                    &mut parse_ua_os(line)
                        .map_err(|err| format_err!("fail to parse `ua_os`: {}, {}", line, err))?
                        .1,
                );
            } else if line.starts_with('[') && line.ends_with(']') {
                cur_mod = Some(
                    parse_module(line)
                        .map_err(|err| format_err!("fail to parse `module`: {}, {}", line, err))?
                        .1,
                );
            } else if let Some((module, direction)) = cur_mod.as_ref() {
                let (_, (name, value)) = parse_named_value(line)
                    .map_err(|err| format_err!("fail to parse named value: {}, {}", line, err))?;

                match name.as_ref() {
                    "label" if module == "mtu" => {
                        mtu.push((value.to_string(), vec![]));
                    }
                    "sig" if module == "mtu" => {
                        if let Some((label, values)) = mtu.last_mut() {
                            let sig = value.parse()?;

                            trace!("`{}` MTU : {}", label, sig);

                            values.push(sig);
                        } else {
                            bail!("`mtu` value without `label`: {}", value);
                        }
                    }
                    "label" => {
                        let (_, label) = parse_label(value).map_err(|err| {
                            format_err!("fail to parse `label`: {}, {}", value, err)
                        })?;

                        match (module.as_str(), direction.as_ref().map(|s| s.as_ref())) {
                            ("tcp", Some("request")) => tcp_request.push((label, vec![])),
                            ("tcp", Some("response")) => tcp_response.push((label, vec![])),
                            ("http", Some("request")) => http_request.push((label, vec![])),
                            ("http", Some("response")) => http_response.push((label, vec![])),
                            _ => {
                                warn!("skip `label` in unknown module `{}`: {}", module, value);
                            }
                        }
                    }
                    "sig" => match (module.as_str(), direction.as_ref().map(|s| s.as_ref())) {
                        ("tcp", Some("request")) => {
                            if let Some((label, values)) = tcp_request.last_mut() {
                                let sig = value.parse()?;

                                trace!("sig for `{}` tcp request: {}", label, sig);

                                values.push(sig);
                            } else {
                                bail!("tcp signature without `label`: {}", value)
                            }
                        }
                        ("tcp", Some("response")) => {
                            if let Some((label, values)) = tcp_response.last_mut() {
                                let sig = value.parse()?;

                                trace!("sig for `{}` tcp response: {}", label, sig);

                                values.push(sig);
                            } else {
                                bail!("tcp signature without `label`: {}", value)
                            }
                        }
                        ("http", Some("request")) => {
                            if let Some((label, values)) = http_request.last_mut() {
                                let sig = value.parse()?;

                                trace!("sig for `{}` http request: {}", label, sig);

                                values.push(sig);
                            } else {
                                bail!("http signature without `label`: {}", value)
                            }
                        }
                        ("http", Some("response")) => {
                            if let Some((label, values)) = http_response.last_mut() {
                                let sig = value.parse()?;

                                trace!("sig for `{}` http response: {}", label, sig);

                                values.push(sig);
                            } else {
                                bail!("http signature without `label`: {}", value)
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
            } else {
                bail!("unexpected line outside the module: {}", line);
            }
        }

        Ok(Database {
            classes,
            mtu,
            ua_os,
            tcp_request,
            tcp_response,
            http_request,
            http_response,
        })
    }
}

macro_rules! impl_from_str {
    ($ty:ty, $parse:ident) => {
        impl FromStr for $ty {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let (remaining, res) = $parse(CompleteStr(s)).map_err(|err| {
                    format_err!("parse {} failed: {}, {}", stringify!($ty), s, err)
                })?;

                if !remaining.is_empty() {
                    Err(format_err!(
                        "parse {} failed, remaining: {}",
                        stringify!($ty),
                        remaining
                    ))
                } else {
                    Ok(res)
                }
            }
        }
    };
}

impl_from_str!(Label, parse_label);
impl_from_str!(Type, parse_type);
impl_from_str!(TcpSignature, parse_tcp_signature);
impl_from_str!(IpVersion, parse_ip_version);
impl_from_str!(Ttl, parse_ttl);
impl_from_str!(WindowSize, parse_window_size);
impl_from_str!(TcpOption, parse_tcp_option);
impl_from_str!(Quirk, parse_quirk);
impl_from_str!(PayloadSize, parse_payload_size);
impl_from_str!(HttpSignature, parse_http_signature);
impl_from_str!(HttpHeader, parse_http_header);

fn parse_named_value(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, (name, _, _, _, value)) =
        tuple((alphanumeric1, space0, tag("="), space0, rest))(input)?;
    Ok((input, (name, value)))
}

fn parse_classes(input: &str) -> IResult<&str, Vec<String>> {
    let (input, (_, _, _, _, classes)) = tuple((
        tag("classes"),
        space0,
        tag("="),
        space0,
        separated_list0(tag(","), alphanumeric1),
    ))(input)?;

    let class_vec = classes.into_iter().map(|s| s.to_string()).collect();
    Ok((input, class_vec))
}

fn parse_module(input: &str) -> IResult<&str, (String, Option<String>)> {
    let (input, (_, module, direction, _)) =
        tuple((tag("["), alpha1, opt(preceded(tag(":"), alpha1)), tag("]")))(input)?;
    let module_str = module.to_string();
    let direction_str = direction.map(|s| s.to_string());

    Ok((input, (module_str, direction_str)))
}

fn parse_ua_os(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    let (input, (_, _, _, _, values)) = tuple((
        tag("ua_os"),
        space0,
        tag("="),
        space0,
        separated_list0(tag(","), parse_key_value),
    ))(input)?;

    let result = values
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
        .collect();

    Ok((input, result))
}

fn parse_key_value(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let (input, (name, _, value)) = tuple((
        alphanumeric1,
        space0,
        opt(preceded(tuple((space0, tag("="), space0)), alphanumeric1)),
    ))(input)?;

    Ok((input, (name, value)))
}

#[rustfmt::skip]
named!(
    parse_label<CompleteStr, Label>,
    do_parse!(
        ty: parse_type >>
        tag!(":") >>
        class: alt!(
            tag!("!") => { |_| None } |
            take_until!(":") => { |s: CompleteStr| Some(s.to_string()) }
        ) >>
        tag!(":") >>
        name: take_until_and_consume!(":") >>
        flavor: rest >>
        (
            Label {
                ty,
                class,
                name: name.to_string(),
                flavor: if flavor.is_empty() {
                    None
                } else {
                    Some(flavor.to_string())
                },
            }
        )
    )
);

named!(parse_type<CompleteStr, Type>, alt!(
    tag!("s") => { |_| Type::Specified } |
    tag!("g") => { |_| Type::Generic }
));

#[rustfmt::skip]
named!(
    parse_tcp_signature<CompleteStr, TcpSignature>,
    do_parse!(
        version: parse_ip_version >>
        tag!(":") >>
        ittl: parse_ttl >>
        tag!(":") >>
        olen: map_res!(digit, |s: CompleteStr| s.parse()) >>
        tag!(":") >>
        mss: alt!(
            tag!("*")                                   => { |_| None } |
            map_res!(digit, |s: CompleteStr| s.parse()) => { Some }
        ) >>
        tag!(":") >>
        wsize: parse_window_size >>
        tag!(",") >>
        wscale: alt!(
            tag!("*")                                   => { |_| None } |
            map_res!(digit, |s: CompleteStr| s.parse()) => { Some }
        ) >>
        tag!(":") >>
        olayout: separated_nonempty_list!(tag!(","), parse_tcp_option) >>
        tag!(":") >>
        quirks: separated_list!(tag!(","), parse_quirk) >>
        tag!(":") >>
        pclass: parse_payload_size >>
        (
            TcpSignature {
                version,
                ittl,
                olen,
                mss,
                wsize,
                wscale,
                olayout,
                quirks,
                pclass,
            }
        )
    )
);

fn parse_ip_version(input: &str) -> IResult<&str, IpVersion> {
    alt((
        map(tag("4"), |_| IpVersion::V4),
        map(tag("6"), |_| IpVersion::V6),
        map(tag("*"), |_| IpVersion::Any),
    ))(input)
}

fn parse_ttl(input: &str) -> IResult<&str, Ttl> {
    alt((
        map_res(terminated(digit1, tag("-")), |s: &str| {
            s.parse::<u8>().map(Ttl::Bad)
        }),
        map_res(terminated(digit1, tag("+?")), |s: &str| {
            s.parse::<u8>().map(Ttl::Guess)
        }),
        map_res(
            separated_pair(digit1, tag("+"), digit1),
            |(ttl_str, distance_str): (&str, &str)| {
                let ttl = ttl_str.parse::<u8>().map_err(|_| "parse ttl")?;
                let distance = distance_str.parse::<u8>().map_err(|_| "parse distance")?;
                Ok(Ttl::Distance(ttl, distance))
            },
        ),
        map_res(digit1, |s: &str| s.parse::<u8>().map(Ttl::Value)),
    ))(input)
}

fn parse_window_size(input: &str) -> IResult<&str, WindowSize> {
    alt((
        map_res(tag("*"), |_| Ok(WindowSize::Any)),
        map_res(preceded(tag("mss*"), digit1), |s: &str| {
            s.parse::<u8>().map(WindowSize::Mss)
        }),
        map_res(preceded(tag("mtu*"), digit1), |s: &str| {
            s.parse::<u8>().map(WindowSize::Mtu)
        }),
        map_res(preceded(tag("%"), digit1), |s: &str| {
            s.parse::<u16>().map(WindowSize::Mod)
        }),
        map_res(digit1, |s: &str| s.parse::<u16>().map(WindowSize::Value)),
    ))(input)
}

named!(parse_tcp_option<CompleteStr, TcpOption>, alt_complete!(
    map_res!(preceded!(tag!("eol+"), digit), |s: CompleteStr| s.parse()) => { TcpOption::Eol } |
    tag!("nop")     => { |_| TcpOption::Nop } |
    tag!("mss")     => { |_| TcpOption::Mss } |
    tag!("ws")      => { |_| TcpOption::Ws } |
    tag!("sok")     => { |_| TcpOption::Sok } |
    tag!("sack")    => { |_| TcpOption::Sack } |
    tag!("ts")      => { |_| TcpOption::TS } |
    map_res!(preceded!(tag!("?"), digit), |s: CompleteStr| s.parse()) => { TcpOption::Unknown }
));

named!(parse_quirk<CompleteStr, Quirk>, alt_complete!(
    tag!("df")      => { |_| Quirk::Df } |
    tag!("id+")     => { |_| Quirk::NonZeroID } |
    tag!("id-")     => { |_| Quirk::ZeroID } |
    tag!("ecn")     => { |_| Quirk::Ecn } |
    tag!("0+")      => { |_| Quirk::MustBeZero } |
    tag!("flow")    => { |_| Quirk::FlowID } |
    tag!("seq-")    => { |_| Quirk::SeqNumZero } |
    tag!("ack+")    => { |_| Quirk::AckNumNonZero } |
    tag!("ack-")    => { |_| Quirk::AckNumZero } |
    tag!("uptr+")   => { |_| Quirk::NonZeroURG } |
    tag!("urgf+")   => { |_| Quirk::Urg } |
    tag!("pushf+")  => { |_| Quirk::Push } |
    tag!("ts1-")    => { |_| Quirk::OwnTimestampZero } |
    tag!("ts2+")    => { |_| Quirk::PeerTimestampNonZero } |
    tag!("opt+")    => { |_| Quirk::TrailinigNonZero } |
    tag!("exws")    => { |_| Quirk::ExcessiveWindowScaling } |
    tag!("bad")     => { |_| Quirk::OptBad }
));

named!(parse_payload_size<CompleteStr, PayloadSize>, alt!(
    tag!("0") => { |_| PayloadSize::Zero } |
    tag!("+") => { |_| PayloadSize::NonZero } |
    tag!("*") => { |_| PayloadSize::Any }
));

named!(parse_http_signature<CompleteStr, HttpSignature>, do_parse!(
    version: parse_http_version >>
    tag!(":") >>
    horder: separated_nonempty_list!(tag!(","), parse_http_header) >>
    tag!(":") >>
    habsent: opt!(separated_list_complete!(tag!(","), parse_http_header)) >>
    tag!(":") >>
    expsw: rest >>
    (
        HttpSignature {
            version,
            horder,
            habsent: habsent.unwrap_or_default(),
            expsw: expsw.to_string(),
        }
    )
));

fn parse_http_version(input: &str) -> IResult<&str, HttpVersion> {
    alt((
        map(tag("0"), |_| HttpVersion::V10),
        map(tag("1"), |_| HttpVersion::V11),
        map(tag("*"), |_| HttpVersion::Any),
    ))(input)
}

fn parse_http_header(input: &str) -> IResult<&str, HttpHeader> {
    map(
        preceded(opt(tag("?")), parse_header_key_value),
        |(name, value): (String, Option<String>)| HttpHeader {
            optional: value.is_none(),
            name,
            value: value.map(|s| s.to_string()),
        },
    )(input)
}

fn parse_header_key_value(input: &str) -> IResult<&str, (String, Option<String>)> {
    separated_pair(
        take_while(|c: char| c.is_ascii_alphanumeric() || c == '-' && c != ':' && c != '='),
        tag("="),
        opt(preceded(tag("=["), take_while(|c: char| c != ']'))),
    )(input)
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::*;
    use crate::http::header;
    use crate::tcp::{Quirk::*, TcpOption::*};

    lazy_static! {
        static ref LABELS: Vec<(&'static str, Label)> = vec![
            (
                "s:!:Uncle John's Networked ls Utility:2.3.0.1",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "Uncle John's Networked ls Utility".to_owned(),
                    flavor: Some("2.3.0.1".to_owned()),
                },
            ),
            (
                "s:unix:Linux:3.11 and newer",
                Label {
                    ty: Type::Specified,
                    class: Some("unix".to_owned()),
                    name: "Linux".to_owned(),
                    flavor: Some("3.11 and newer".to_owned()),
                },
            ),
            (
                "s:!:Chrome:11.x to 26.x",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "Chrome".to_owned(),
                    flavor: Some("11.x to 26.x".to_owned()),
                },
            ),
            (
                "s:!:curl:",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "curl".to_owned(),
                    flavor: None,
                },
            )
        ];
        static ref TCP_SIGNATURES: Vec<(&'static str, TcpSignature)> = vec![
            (
                "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Mss(20),
                    wscale: Some(10),
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64:0:*:16384,0:mss::0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Value(16384),
                    wscale: Some(0),
                    olayout: vec![Mss],
                    quirks: vec![],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "4:128:0:1460:mtu*2,0:mss,nop,ws::0",
                TcpSignature {
                    version: IpVersion::V4,
                    ittl: Ttl::Value(128),
                    olen: 0,
                    mss: Some(1460),
                    wsize: WindowSize::Mtu(2),
                    wscale: Some(0),
                    olayout: vec![Mss, Nop, Ws],
                    quirks: vec![],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64-:0:265:%512,0:mss,sok,ts:ack+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Bad(64),
                    olen: 0,
                    mss: Some(265),
                    wsize: WindowSize::Mod(512),
                    wscale: Some(0),
                    olayout: vec![Mss, Sok, TS],
                    quirks: vec![AckNumNonZero],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Mss(44),
                    wscale: Some(1),
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64:0:*:*,*:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Any,
                    wscale: None,
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                }

            )
        ];
        static ref TTLS: Vec<(&'static str, Ttl)> = vec![
            (
                "64",
                Ttl::Value(64)
            ),
            (
                "54+10",
                Ttl::Distance(54, 10)
            ),
            (
                "64-",
                Ttl::Bad(64)
            ),
            (
                "54+?",
                Ttl::Guess(54)
            )
        ];
        static ref HTTP_SIGNATURES: Vec<(&'static str, HttpSignature)> = vec![
            (
                "*:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip,deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],Keep-Alive=[300],Connection=[keep-alive]::Firefox/",
                HttpSignature {
                    version: HttpVersion::Any,
                    horder: vec![
                        header("Host"),
                        header("User-Agent"),
                        header("Accept").with_value(",*/*;q="),
                        header("Accept-Language").optional(),
                        header("Accept-Encoding").with_value("gzip,deflate"),
                        header("Accept-Charset").with_value("utf-8;q=0.7,*;q=0.7"),
                        header("Keep-Alive").with_value("300"),
                        header("Connection").with_value("keep-alive"),
                    ],
                    habsent: vec![],
                    expsw: "Firefox/".to_owned(),
                }
            )
        ];
        static ref HTTP_HEADERS: Vec<(&'static str, HttpHeader)> = vec![
            ("Host", HttpHeader{ optional: false, name: "Host".to_owned(), value: None}),
            ("User-Agent", HttpHeader{ optional: false, name: "User-Agent".to_owned(), value: None}),
            ("Accept=[,*/*;q=]", HttpHeader{ optional: false, name: "Accept".to_owned(), value: Some(",*/*;q=".to_owned())}),
            ("?Accept-Language", HttpHeader{ optional: true, name: "Accept-Language".to_owned(), value: None}),
        ];
    }

    #[test]
    fn test_label() {
        for (s, l) in LABELS.iter() {
            assert_eq!(&s.parse::<Label>().unwrap(), l);
        }
    }

    #[test]
    fn test_tcp_signature() {
        for (s, sig) in TCP_SIGNATURES.iter() {
            assert_eq!(&s.parse::<TcpSignature>().unwrap(), sig);
            assert_eq!(&sig.to_string(), s);
        }
    }

    #[test]
    fn test_ttl() {
        for (s, ttl) in TTLS.iter() {
            assert_eq!(&s.parse::<Ttl>().unwrap(), ttl);
            assert_eq!(&ttl.to_string(), s);
        }
    }

    #[test]
    fn test_http_signature() {
        for (s, sig) in HTTP_SIGNATURES.iter() {
            assert_eq!(&s.parse::<HttpSignature>().unwrap(), sig);
            assert_eq!(&sig.to_string(), s);
        }
    }

    #[test]
    fn test_http_header() {
        for (s, h) in HTTP_HEADERS.iter() {
            assert_eq!(&s.parse::<HttpHeader>().unwrap(), h);
            assert_eq!(&h.to_string(), s);
        }
    }
}
