//! [`Label`] and [`Type`]: signature metadata from the p0f database format.

use std::fmt;

/// Signature metadata from a p0f-style label (`s`/`g`:`class`:`name`:`flavor`).
///
/// For TCP, `class: None` is p0f's `!` (userland tool such as NMap), not a
/// missing OS family. HTTP browser/server labels often have no class either;
/// that is unrelated to the fuzzy-userland gate, which only applies to TCP.
#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub ty: Type,
    pub class: Option<String>,
    pub name: String,
    pub flavor: Option<String>,
}

impl Label {
    /// p0f userland entry (`s:!:…` / `g:!:…`): no OS class, so a fuzzy match
    /// must not be reported (guessing which tool sent an approximate packet is
    /// worse than saying nothing). Exact matches against userland still count.
    pub fn is_userland(&self) -> bool {
        self.class.is_none()
    }
}

/// Enum representing the type of `Label`.
/// - `Specified`: A specific label with well-defined characteristics.
/// - `Generic`: A generic label with broader characteristics.
#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Specified,
    Generic,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.ty,
            self.class.as_deref().unwrap_or_default(),
            self.name,
            self.flavor.as_deref().unwrap_or_default()
        )
    }
}
