use huginn_net_db::tcp::Ttl;
use huginn_net_tcp::ttl::{calculate_ttl, guess_distance};

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
