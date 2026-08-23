//! UA vs observed-OS agreement (p0f `NAT_APP_UA`).
//!
//! Free function plus the types the caller needs to inject an observed OS.
//! No host cache lives here: if the caller can answer, it answers.

use crate::http::UNKNOWN_SOFTWARE;
use crate::matcher_api::{HttpMatcher, HttpRequestMatch};
use std::fmt;
use std::net::IpAddr;

/// OS observed on the network for this connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct ObservedOs {
    pub name: String,
}

/// What the caller satisfies. Mirrors [`HttpMatcher`]: `huginn-net-http`
/// does not depend on TCP; the caller plugs the source in.
pub trait ObservedOsSource: Send + Sync {
    /// Look up the OS seen for this client. Only the client side is required:
    /// the ephemeral port identifies the connection, which is how the TCP
    /// side already indexes SYNs.
    fn observed_os(&self, client: IpAddr, client_port: u16) -> Option<ObservedOs>;
}

/// How the caller resolved the observed-OS lookup, so
/// [`UaOsAgreement::NotChecked`] can tell "no provider" from "provider
/// returned none".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedOsInput<'a> {
    /// No [`ObservedOsSource`] was plugged in.
    NoSource,
    /// A source was plugged in and returned `None`.
    Missing,
    Present(&'a ObservedOs),
}

/// Why [`check_ua_os_agreement`] did not emit Consistent/Divergent.
///
/// Order matches p0f `score_nat`: earlier gates win. A standalone caller
/// without a provider still sees HTTP-side reasons; [`Self::NoSource`]
/// only appears when the check would have compared OS names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum NotCheckedReason {
    NoMatch,
    NotUserlandApp,
    NoUserAgent,
    Dishonest,
    UaNotInTable,
    NoSource,
    NoObservedOs,
}

impl fmt::Display for NotCheckedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoMatch => "no match",
            Self::NotUserlandApp => "not userland app",
            Self::NoUserAgent => "no user-agent",
            Self::Dishonest => "dishonest",
            Self::UaNotInTable => "ua not in table",
            Self::NoSource => "no source",
            Self::NoObservedOs => "no observed os",
        })
    }
}

/// UA-claimed OS vs network-observed OS.
///
/// [`Self::Divergent`] is p0f `NAT_APP_UA`: evidence of NAT/proxy, not of a
/// client lying.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum UaOsAgreement {
    NotChecked(NotCheckedReason),
    Consistent { os: String },
    Divergent { ua_os: String, network_os: String },
}

impl fmt::Display for UaOsAgreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotChecked(reason) => write!(f, "not checked ({reason})"),
            Self::Consistent { os } => write!(f, "consistent ({os})"),
            Self::Divergent { ua_os, network_os } => {
                write!(f, "divergent (ua={ua_os}, net={network_os})")
            }
        }
    }
}

fn usable_user_agent(ua: Option<&str>) -> Option<&str> {
    let ua = ua
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != UNKNOWN_SOFTWARE)?;
    Some(ua)
}

pub fn check_ua_os_agreement(
    ua: Option<&str>,
    matched: Option<&HttpRequestMatch>,
    matcher: Option<&dyn HttpMatcher>,
    observed: ObservedOsInput<'_>,
) -> UaOsAgreement {
    let Some(matched) = matched else {
        return UaOsAgreement::NotChecked(NotCheckedReason::NoMatch);
    };
    if matched.browser.family.is_some() {
        return UaOsAgreement::NotChecked(NotCheckedReason::NotUserlandApp);
    }
    let Some(ua) = usable_user_agent(ua) else {
        return UaOsAgreement::NotChecked(NotCheckedReason::NoUserAgent);
    };
    if matched.dishonest {
        return UaOsAgreement::NotChecked(NotCheckedReason::Dishonest);
    }
    let Some(ua_os) = matcher.and_then(|m| m.match_user_agent(ua)) else {
        return UaOsAgreement::NotChecked(NotCheckedReason::UaNotInTable);
    };
    let observed = match observed {
        ObservedOsInput::NoSource => {
            return UaOsAgreement::NotChecked(NotCheckedReason::NoSource);
        }
        ObservedOsInput::Missing => {
            return UaOsAgreement::NotChecked(NotCheckedReason::NoObservedOs);
        }
        ObservedOsInput::Present(os) => os,
    };
    if ua_os.family == observed.name {
        UaOsAgreement::Consistent { os: ua_os.family }
    } else {
        UaOsAgreement::Divergent { ua_os: ua_os.family, network_os: observed.name.clone() }
    }
}
