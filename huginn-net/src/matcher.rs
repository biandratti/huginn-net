/// Macro for quality matching pattern.
/// This macro provides a zero-cost abstraction for the common pattern of
/// conditional quality matching based on matcher_enabled configuration.
///
/// # Usage
///
/// ```rust
/// use huginn_net::quality_match;
/// # use huginn_net_tcp::output::{OperativeSystem, OSQualityMatched};
/// # use huginn_net_db::{MatchQualityType, Label};
/// # struct Config { matcher_enabled: bool }
/// # struct Matcher;
/// # struct ObservableTcp;
/// # let config = Config { matcher_enabled: true };
/// # let matcher: Option<Matcher> = None;
/// # let observable_tcp = ObservableTcp;
/// let quality = quality_match!(
///     enabled: config.matcher_enabled,
///     matcher: matcher,
///     call: matcher => None::<(Label, String, f32)>,
///     matched: (label, _signature, quality) => OSQualityMatched {
///         os: Some(OperativeSystem::from(&label)),
///         quality: MatchQualityType::Matched(quality),
///     },
///     not_matched: OSQualityMatched {
///         os: None,
///         quality: MatchQualityType::NotMatched,
///     },
///     disabled: OSQualityMatched {
///         os: None,
///         quality: MatchQualityType::Disabled,
///     }
/// );
/// ```
#[macro_export]
macro_rules! quality_match {
    (
        enabled: $enabled:expr,
        matcher: $matcher:expr,
        call: $matcher_var:ident => $call:expr,
        matched: $result:pat => $matched_expr:expr,
        not_matched: $not_matched_expr:expr,
        disabled: $disabled_expr:expr
    ) => {
        if $enabled {
            $matcher
                .as_ref()
                .and_then(|$matcher_var| $call)
                .map(|$result| $matched_expr)
                .unwrap_or($not_matched_expr)
        } else {
            $disabled_expr
        }
    };
}

/// Simplified quality matching macro for cases where the matcher call is straightforward.
///
/// This is a convenience macro for the most common use case where you just need
/// to call a single matcher method and handle the three states.
///
/// # Usage
///
/// ```rust
/// use huginn_net::{simple_quality_match, quality_match};
/// # use huginn_net_tcp::output::MTUQualityMatched;
/// # use huginn_net_db::MatchQualityType;
/// # struct Config { matcher_enabled: bool }
/// # struct Matcher;
/// # impl Matcher {
/// #     fn matching_by_mtu(&self, _value: &u16) -> Option<(String, String)> { None }
/// # }
/// # struct ObservableMtu { value: u16 }
/// # let config = Config { matcher_enabled: true };
/// # let matcher: Option<Matcher> = None;
/// # let observable_mtu = ObservableMtu { value: 1500 };
/// let quality = simple_quality_match!(
///     enabled: config.matcher_enabled,
///     matcher: matcher,
///     method: matching_by_mtu(&observable_mtu.value),
///     success: (link, _) => MTUQualityMatched {
///         link: Some(link.clone()),
///         quality: MatchQualityType::Matched(1.0),
///     },
///     failure: MTUQualityMatched {
///         link: None,
///         quality: MatchQualityType::NotMatched,
///     },
///     disabled: MTUQualityMatched {
///         link: None,
///         quality: MatchQualityType::Disabled,
///     }
/// );
/// ```
#[macro_export]
macro_rules! simple_quality_match {
    (
        enabled: $enabled:expr,
        matcher: $matcher:expr,
        method: $method:ident($($args:expr),*),
        success: $result:pat => $success_expr:expr,
        failure: $failure_expr:expr,
        disabled: $disabled_expr:expr
    ) => {
        quality_match!(
            enabled: $enabled,
            matcher: $matcher,
            call: matcher => matcher.$method($($args),*),
            matched: $result => $success_expr,
            not_matched: $failure_expr,
            disabled: $disabled_expr
        )
    };
}
