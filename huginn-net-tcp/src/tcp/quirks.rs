//! Quirk bitmask (`QuirkSet`) aligned with p0f's `QUIRK_*` in `process.h`.

use super::Quirk;
use core::fmt;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

/// Set of TCP/IP quirks as a `u32` bitmask (p0f `pk.quirks` / `sig->quirks`).
///
/// Individual quirks stay as [`Quirk`] for parsing and naming; matching uses
/// bitwise ops on this type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct QuirkSet(u32);

impl QuirkSet {
    pub const EMPTY: Self = Self(0);

    /// Bits that may disappear from traffic vs the signature (`df`, `id+`).
    pub const FUZZY_DELETABLE: Self = Self(Quirk::Df.bit() | Quirk::NonZeroID.bit());

    /// Bits that may appear in traffic beyond the signature (`id-`, `ecn`).
    pub const FUZZY_ADDABLE: Self = Self(Quirk::ZeroID.bit() | Quirk::Ecn.bit());

    /// Cleared from a version-agnostic signature when the observation is IPv4.
    pub const MASK_WHEN_OBS_V4: Self = Self(Quirk::FlowID.bit());

    /// Cleared from a version-agnostic signature when the observation is IPv6.
    pub const MASK_WHEN_OBS_V6: Self =
        Self(Quirk::Df.bit() | Quirk::NonZeroID.bit() | Quirk::ZeroID.bit());

    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn contains(self, quirk: Quirk) -> bool {
        self.0 & quirk.bit() != 0
    }

    #[inline]
    pub fn insert(&mut self, quirk: Quirk) {
        self.0 |= quirk.bit();
    }

    #[inline]
    pub const fn with(self, quirk: Quirk) -> Self {
        Self(self.0 | quirk.bit())
    }

    /// Quirks present in `self` but not in `other`.
    #[inline]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Iterate quirks in p0f `.fp` declaration order (for Display / FuzzyReason).
    pub fn iter(self) -> impl Iterator<Item = Quirk> {
        DISPLAY_ORDER
            .iter()
            .copied()
            .filter(move |q| self.contains(*q))
    }
}

impl FromIterator<Quirk> for QuirkSet {
    fn from_iter<T: IntoIterator<Item = Quirk>>(iter: T) -> Self {
        let mut set = Self::EMPTY;
        for q in iter {
            set.insert(q);
        }
        set
    }
}

impl From<&[Quirk]> for QuirkSet {
    fn from(quirks: &[Quirk]) -> Self {
        quirks.iter().copied().collect()
    }
}

impl<const N: usize> From<[Quirk; N]> for QuirkSet {
    fn from(quirks: [Quirk; N]) -> Self {
        quirks.into_iter().collect()
    }
}

impl BitOr for QuirkSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for QuirkSet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for QuirkSet {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for QuirkSet {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for QuirkSet {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl fmt::Display for QuirkSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for quirk in self.iter() {
            if !first {
                f.write_str(",")?;
            }
            write!(f, "{quirk}")?;
            first = false;
        }
        Ok(())
    }
}

/// Order used when rendering quirks (matches p0f `.fp` / `fp_tcp.c` parse order).
const DISPLAY_ORDER: &[Quirk] = &[
    Quirk::Df,
    Quirk::NonZeroID,
    Quirk::ZeroID,
    Quirk::Ecn,
    Quirk::MustBeZero,
    Quirk::FlowID,
    Quirk::SeqNumZero,
    Quirk::AckNumNonZero,
    Quirk::AckNumZero,
    Quirk::NonZeroURG,
    Quirk::Urg,
    Quirk::Push,
    Quirk::OwnTimestampZero,
    Quirk::PeerTimestampNonZero,
    Quirk::TrailinigNonZero,
    Quirk::ExcessiveWindowScaling,
    Quirk::OptBad,
];

impl Quirk {
    /// Bit in [`QuirkSet`] / p0f `QUIRK_*`.
    pub const fn bit(self) -> u32 {
        match self {
            Quirk::Ecn => 0x0000_0001,
            Quirk::Df => 0x0000_0002,
            Quirk::NonZeroID => 0x0000_0004,
            Quirk::ZeroID => 0x0000_0008,
            Quirk::MustBeZero => 0x0000_0010,
            Quirk::FlowID => 0x0000_0020,
            Quirk::SeqNumZero => 0x0000_1000,
            Quirk::AckNumNonZero => 0x0000_2000,
            Quirk::AckNumZero => 0x0000_4000,
            Quirk::NonZeroURG => 0x0000_8000,
            Quirk::Urg => 0x0001_0000,
            Quirk::Push => 0x0002_0000,
            Quirk::OwnTimestampZero => 0x0100_0000,
            Quirk::PeerTimestampNonZero => 0x0200_0000,
            Quirk::TrailinigNonZero => 0x0400_0000,
            Quirk::ExcessiveWindowScaling => 0x0800_0000,
            Quirk::OptBad => 0x1000_0000,
        }
    }
}
