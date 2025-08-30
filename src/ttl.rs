use crate::tcp::Ttl;

fn guess_distance(ttl: u8) -> u8 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_distance() {
        assert_eq!(guess_distance(32), 0);
        assert_eq!(guess_distance(64), 0);
        assert_eq!(guess_distance(128), 0);
        assert_eq!(guess_distance(255), 0);

        assert_eq!(guess_distance(30), 2);
        assert_eq!(guess_distance(60), 4);
        assert_eq!(guess_distance(120), 8);
        assert_eq!(guess_distance(200), 55);

        assert_eq!(guess_distance(1), 31);
        assert_eq!(guess_distance(33), 31);
        assert_eq!(guess_distance(65), 63);
        assert_eq!(guess_distance(129), 126);
    }

    #[test]
    fn test_calculate_bad_ttl() {
        assert_eq!(calculate_ttl(0), Ttl::Bad(0));
    }

    #[test]
    fn test_calculate_ttl_standard_initial_values() {
        assert_eq!(calculate_ttl(32), Ttl::Distance(32, 0));
        assert_eq!(calculate_ttl(64), Ttl::Distance(64, 0));
        assert_eq!(calculate_ttl(128), Ttl::Distance(128, 0));
        assert_eq!(calculate_ttl(255), Ttl::Distance(255, 0));
    }

    #[test]
    fn test_calculate_ttl_acceptable_distances() {
        // TTLs within MAX_HOPS_ACCEPTABLE (30) should return Distance
        assert_eq!(calculate_ttl(57), Ttl::Distance(57, 7));
        assert_eq!(calculate_ttl(120), Ttl::Distance(120, 8));
        assert_eq!(calculate_ttl(240), Ttl::Distance(240, 15));
        assert_eq!(calculate_ttl(20), Ttl::Distance(20, 12));
        assert_eq!(calculate_ttl(34), Ttl::Distance(34, 30));
    }

    #[test]
    fn test_calculate_ttl_excessive_distances() {
        // TTLs with distance > MAX_HOPS_ACCEPTABLE should return Value
        assert_eq!(calculate_ttl(1), Ttl::Value(1));
        assert_eq!(calculate_ttl(33), Ttl::Value(33));
        assert_eq!(calculate_ttl(97), Ttl::Value(97));
        assert_eq!(calculate_ttl(150), Ttl::Value(150));
        assert_eq!(calculate_ttl(224), Ttl::Value(224));
    }
}
