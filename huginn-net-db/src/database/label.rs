//! [`Label`] and [`Type`] — signature metadata from the p0f database format.

use std::fmt;

/// Represents a label associated with a signature, which provides metadata about
/// the signature, such as type, class, name, and optional flavor details.
#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub ty: Type,
    pub class: Option<String>,
    pub name: String,
    pub flavor: Option<String>,
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
