use super::common::{impl_from_str, str_parser};
use crate::tcp::{
    IpVersion, PayloadSize, Quirk, Signature as TcpSignature, TcpOption, Ttl, WindowSize,
};
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::digit1;
use nom::combinator::{map, map_res};
use nom::multi::{separated_list0, separated_list1};
use nom::sequence::{preceded, separated_pair, terminated};
use nom::{IResult, Parser};

impl_from_str!(TcpSignature, parse_tcp_signature);
str_parser!(parse_ip_version_str, IpVersion, parse_ip_version);
str_parser!(parse_ttl_str, Ttl, parse_ttl);
str_parser!(parse_window_size_str, WindowSize, parse_window_size);
str_parser!(parse_tcp_option_str, TcpOption, parse_tcp_option);
str_parser!(parse_quirk_str, Quirk, parse_quirk);
str_parser!(parse_payload_size_str, PayloadSize, parse_payload_size);

pub(super) fn parse_tcp_signature(input: &str) -> IResult<&str, TcpSignature> {
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

fn parse_ip_version(input: &str) -> IResult<&str, IpVersion> {
    alt((
        map(tag("4"), |_| IpVersion::V4),
        map(tag("6"), |_| IpVersion::V6),
        map(tag("*"), |_| IpVersion::Any),
    ))
    .parse(input)
}

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

fn parse_payload_size(input: &str) -> IResult<&str, PayloadSize> {
    alt((
        map(tag("0"), |_| PayloadSize::Zero),
        map(tag("+"), |_| PayloadSize::NonZero),
        map(tag("*"), |_| PayloadSize::Any),
    ))
    .parse(input)
}
