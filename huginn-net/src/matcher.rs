/// Macro for quality matching pattern.
/// This macro provides a zero-cost abstraction for the common pattern of
/// conditional quality matching based on matcher_enabled configuration.
///
/// # Usage
///
/// The doctest below uses synthetic types so it builds whether or not the
/// optional `db` feature is enabled, `huginn_net_db::Label` is feature-gated
/// behind `db`, so the macro is documented against generic shapes instead.
///
/// ```rust
/// use huginn_net::quality_match;
/// # struct Config { matcher_enabled: bool }
/// # struct Matcher;
/// # struct Output { name: Option<String> }
/// # let config = Config { matcher_enabled: true };
/// # let matcher: Option<Matcher> = None;
/// let out: Output = quality_match!(
///     enabled: config.matcher_enabled,
///     matcher: matcher,
///     call: _m => None::<(String, String, f32)>,
///     matched: (name, _signature, _quality) => Output { name: Some(name) },
///     not_matched: Output { name: None },
///     disabled: Output { name: None }
/// );
/// # let _ = out;
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
/// Like [`quality_match!`], the doctest is written against synthetic types so
/// it compiles independent of optional features.
///
/// ```rust
/// use huginn_net::{simple_quality_match, quality_match};
/// # struct Config { matcher_enabled: bool }
/// # struct Matcher;
/// # impl Matcher {
/// #     fn matching_by_mtu(&self, _value: &u16) -> Option<(String, String)> { None }
/// # }
/// # struct ObservableMtu { value: u16 }
/// # struct Output { link: Option<String> }
/// # let config = Config { matcher_enabled: true };
/// # let matcher: Option<Matcher> = None;
/// # let observable_mtu = ObservableMtu { value: 1500 };
/// let out: Output = simple_quality_match!(
///     enabled: config.matcher_enabled,
///     matcher: matcher,
///     method: matching_by_mtu(&observable_mtu.value),
///     success: (link, _) => Output { link: Some(link.clone()) },
///     failure: Output { link: None },
///     disabled: Output { link: None }
/// );
/// # let _ = out;
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
