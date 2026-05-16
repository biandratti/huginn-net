//! Parsers and macros shared by the TCP and HTTP branches of [`super`].

use crate::database::{Label, Type};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until};
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::character::complete::alpha1;
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::character::complete::{alphanumeric1, space0};
use nom::combinator::{map, opt, rest};
#[cfg(any(feature = "tcp", feature = "http"))]
use nom::multi::separated_list0;
use nom::sequence::preceded;
use nom::{IResult, Parser};

macro_rules! impl_from_str {
    ($ty:ty, $parse:ident) => {
        impl ::std::str::FromStr for $ty {
            type Err = $crate::error::DatabaseError;

            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                let (remaining, res) = $parse(s).map_err(|err| {
                    $crate::error::DatabaseError::Parse(format!(
                        "parse {} failed: {}, {}",
                        stringify!($ty),
                        s,
                        err
                    ))
                })?;

                if !remaining.is_empty() {
                    Err($crate::error::DatabaseError::Parse(format!(
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

#[cfg(any(feature = "tcp", feature = "http"))]
pub(crate) use impl_from_str;

#[cfg(any(feature = "tcp", feature = "http"))]
macro_rules! str_parser {
    ($name:ident, $ty:ty, $parse:ident) => {
        pub fn $name(s: &str) -> ::std::result::Result<$ty, $crate::error::DatabaseError> {
            let (remaining, value) = $parse(s).map_err(|err| {
                $crate::error::DatabaseError::Parse(format!(
                    "parse {} failed: {}, {}",
                    stringify!($ty),
                    s,
                    err
                ))
            })?;
            if !remaining.is_empty() {
                Err($crate::error::DatabaseError::Parse(format!(
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
#[cfg(any(feature = "tcp", feature = "http"))]
pub(crate) use str_parser;

impl_from_str!(Label, parse_label);
impl_from_str!(Type, parse_type);

#[cfg(any(feature = "tcp", feature = "http"))]
pub(super) fn parse_named_value(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, (name, _, _, _, value)) =
        (alphanumeric1, space0, tag("="), space0, rest).parse(input)?;
    Ok((input, (name, value)))
}

#[cfg(any(feature = "tcp", feature = "http"))]
pub(super) fn parse_classes(input: &str) -> IResult<&str, Vec<String>> {
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
pub(super) fn parse_module(input: &str) -> IResult<&str, (String, Option<String>)> {
    let (input, (_, module, direction, _)) =
        (tag("["), alpha1, opt(preceded(tag(":"), alpha1)), tag("]")).parse(input)?;
    let module_str = module.to_string();
    let direction_str = direction.map(|s| s.to_string());

    Ok((input, (module_str, direction_str)))
}

pub(super) fn parse_label(input: &str) -> IResult<&str, Label> {
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

pub(super) fn parse_type(input: &str) -> IResult<&str, Type> {
    alt((tag("s").map(|_| Type::Specified), tag("g").map(|_| Type::Generic))).parse(input)
}
