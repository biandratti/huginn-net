use crate::tcp::Ttl;

pub fn guess_distance(ttl: u8) -> u8 {
    if ttl > 128 {
        255u8.saturating_sub(ttl)
    } else if ttl > 64 {
        128u8.saturating_sub(ttl)
    } else if ttl > 32 {
        64u8.saturating_sub(ttl)
    } else {
        32u8.saturating_sub(ttl)
    }
}

const MAX_HOPS_ACCEPTABLE: u8 = 30;

/// Calculate TTL using the Known TTL values from common operating systems
/// TTL_WINDOWS: u8 = 128; // Windows typically uses 128
/// TTL_LINUX: u8 = 64; // Linux typically uses 64
/// TTL_OSX: u8 = 64; // macOS typically uses 64
/// TTL_IOS: u8 = 64; // iOS typically uses 64
/// TTL_ANDROID: u8 = 64; // Android typically uses 64
/// TTL_FREEBSD: u8 = 255; // FreeBSD typically uses 255
///
/// How calculate the ttl:
/// 1. Guess the distance from the observed ttl
/// 2. Determine the likely initial ttl based on the observed ttl range
/// 3. If ttl_observed is 0, return Ttl::Bad(0)
/// 4. If the distance is reasonable (e.g., <= MAX_HOPS_ACCEPTABLE hops), consider it a valid distance calculation
/// 5. If the ttl doesn't match common patterns, classify it as Ttl::Value (raw ttl)
pub fn calculate_ttl(ttl_observed: u8) -> Ttl {
    if ttl_observed == 0 {
        return Ttl::Bad(ttl_observed);
    }
    let distance = guess_distance(ttl_observed);
    if distance <= MAX_HOPS_ACCEPTABLE {
        Ttl::Distance(ttl_observed, distance)
    } else {
        Ttl::Value(ttl_observed)
    }
}
