use super::common::{impl_from_str, str_parser};
use crate::http::{Header as HttpHeader, Signature as HttpSignature, Version as HttpVersion};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until, take_while, take_while1};
use nom::character::complete::{char, space0};
use nom::combinator::{eof, map, opt, rest};
use nom::multi::{separated_list0, separated_list1};
use nom::sequence::{pair, preceded, terminated};
use nom::{IResult, Parser};

impl_from_str!(HttpSignature, parse_http_signature);
str_parser!(parse_http_version_str, HttpVersion, parse_http_version);
str_parser!(parse_http_header_str, HttpHeader, parse_http_header);

pub(super) fn parse_ua_os(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    let (input, (_, _, _, _, values)) = (
        tag("ua_os"),
        space0,
        tag("="),
        space0,
        separated_list0(char(','), parse_ua_os_entry),
    )
        .parse(input)?;
    let (input, _) = space0.parse(input)?;
    let (input, _) = eof.parse(input)?;

    let result = values
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
        .collect();

    Ok((input, result))
}

/// p0f `config.h` `NAME_CHARS`: non-alnum allowed in OS names (`http_parse_ua`).
const UA_OS_NAME_EXTRA: &str = " ./-_!?()";

fn is_ua_os_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || UA_OS_NAME_EXTRA.contains(c)
}

/// One `ua_os` entry: a possibly multi-word family (`Mac OS X`) and an optional
/// `=[substr]` needle (`iOS=[iPad]`, `Solaris=[SunOS]`). Same bracket form as
/// HTTP header values. Names follow p0f: `isalnum` plus `NAME_CHARS`.
fn parse_ua_os_entry(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let (input, _) = space0.parse(input)?;
    let (input, name) = take_while1(is_ua_os_name_char).parse(input)?;
    let name = name.trim_end();
    if name.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TakeWhile1,
        )));
    }
    let (input, value) =
        opt(preceded(tag("=["), terminated(take_until("]"), char(']')))).parse(input)?;
    let (input, _) = space0.parse(input)?;
    Ok((input, (name, value)))
}

pub(super) fn parse_http_signature(input: &str) -> IResult<&str, HttpSignature> {
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

fn parse_http_version(input: &str) -> IResult<&str, HttpVersion> {
    alt((
        map(tag("0"), |_| HttpVersion::V10),
        map(tag("1"), |_| HttpVersion::V11),
        map(tag("*"), |_| HttpVersion::Any),
    ))
    .parse(input)
}

fn parse_header_key_value(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    pair(
        take_while(|c: char| (c.is_ascii_alphanumeric() || c == '-') && c != ':' && c != '='),
        opt(preceded(tag("=["), terminated(take_until("]"), char(']')))),
    )
    .parse(input)
}

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
