use huginn_net_http::http_languages::get_highest_quality_language;

#[test]
fn test_get_highest_quality_language_from_regular_case_with_several_languages() {
    let accept_language = "en;q=0.8,es;q=0.9,fr;q=0.7".to_string();
    let result = get_highest_quality_language(accept_language);
    assert_eq!(result, Some("Spanish".to_string()));
}

#[test]
fn test_get_highest_quality_language_is_first_one() {
    let accept_language = "en;q=1.0,es;q=0.8".to_string();
    let result = get_highest_quality_language(accept_language);
    assert_eq!(result, Some("English".to_string()));
}

#[test]
fn test_get_highest_quality_language_is_last_one() {
    let accept_language = "de;q=0.9,fr;q=1.0".to_string();
    let result = get_highest_quality_language(accept_language);
    assert_eq!(result, Some("French".to_string()));
}

#[test]
fn test_get_highest_quality_language_with_no_quality_specified() {
    let accept_language = "de,fr".to_string();
    let result = get_highest_quality_language(accept_language);
    assert_eq!(result, Some("German".to_string()));
}

#[test]
fn test_get_highest_quality_language_when_variant_used() {
    let accept_language = "en-US;q=0.9,es;q=0.8".to_string();
    let result = get_highest_quality_language(accept_language);
    assert_eq!(result, Some("English".to_string()));
}

#[test]
fn test_get_highest_quality_language_with_only_one_language() {
    let accept_language = "es".to_string();
    let result = get_highest_quality_language(accept_language);
    assert_eq!(result, Some("Spanish".to_string()));
}

#[test]
fn test_get_highest_quality_without_language() {
    let accept_language = "".to_string();
    let result = get_highest_quality_language(accept_language);
    assert_eq!(result, None);
}

#[test]
fn test_get_highest_quality_language_with_malformed_parts() {
    // Test with malformed Accept-Language header containing empty parts and semicolons
    let accept_language = "en;q=0.8,,;q=0.5,es;q=0.9,;,fr;q=0.7".to_string();
    let result = get_highest_quality_language(accept_language);
    // Should still work and return Spanish (highest quality = 0.9)
    assert_eq!(result, Some("Spanish".to_string()));
}
