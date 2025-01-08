use crate::tcp::Ttl;

fn guess_distance(ttl: u8) -> u8 {
    if ttl <= 32 {
        32 - ttl
    } else if ttl <= 64 {
        64 - ttl
    } else if ttl <= 128 {
        128 - ttl
    } else {
        255 - ttl
    }
}

/// Calculate TTL using the Known TTL values from common OSes
/// TTL_WINDOWS: u8 = 128; // Windows typically uses 128
/// TTL_LINUX: u8 = 64; // Linux typically uses 64
/// TTL_OSX: u8 = 64; // macOS typically uses 64
/// TTL_IOS: u8 = 64; // iOS typically uses 64
/// TTL_ANDROID: u8 = 64; // Android typically uses 64
/// TTL_FREEBSD: u8 = 255; // FreeBSD typically uses 255
pub fn calculate_ttl(ttl_observed: u8) -> Ttl {
    if ttl_observed == 0 {
        return Ttl::Bad(ttl_observed); // Bad TTL value
    }

    // Known TTL initial values (this could be extended with more OSes)
    let common_initial_ttl_list = &[64, 128, 255];

    // Check if ttl_observed matches any known initial TTL value
    if let Some(&_initial_ttl) = common_initial_ttl_list
        .iter()
        .find(|&&initial| ttl_observed == initial)
    {
        return Ttl::Distance(ttl_observed, guess_distance(ttl_observed));
    }

    // If TTL doesn't match common initial values, classify it as Ttl::Value (raw TTL)
    Ttl::Value(ttl_observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_distance() {
        assert_eq!(guess_distance(32), 0);
        assert_eq!(guess_distance(64), 0);
        assert_eq!(guess_distance(128), 0);
        assert_eq!(guess_distance(200), 55);
        assert_eq!(guess_distance(255), 0);
    }

    #[test]
    fn test_calculate_bad_ttl() {
        assert_eq!(calculate_ttl(0), Ttl::Bad(0));
    }

    #[test]
    fn test_calculate_distance_ttl() {
        assert_eq!(calculate_ttl(64), Ttl::Distance(64, 0));
        assert_eq!(calculate_ttl(128), Ttl::Distance(128, 0));
        assert_eq!(calculate_ttl(255), Ttl::Distance(255, 0));
    }

    #[test]
    fn test_calculate_not_match_known_pattern_ttl() {
        assert_eq!(calculate_ttl(20), Ttl::Value(20));
        assert_eq!(calculate_ttl(32), Ttl::Value(32));
        assert_eq!(calculate_ttl(150), Ttl::Value(150));
        assert_eq!(calculate_ttl(200), Ttl::Value(200));
    }
}
