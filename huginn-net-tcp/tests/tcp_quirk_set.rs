use huginn_net_tcp::tcp::{Quirk, QuirkSet};

#[test]
fn bits_match_p0f_process_h() {
    assert_eq!(Quirk::Ecn.bit(), 0x0000_0001);
    assert_eq!(Quirk::Df.bit(), 0x0000_0002);
    assert_eq!(Quirk::NonZeroID.bit(), 0x0000_0004);
    assert_eq!(Quirk::OptBad.bit(), 0x1000_0000);
}

#[test]
fn display_follows_fp_declaration_order() {
    let set = QuirkSet::from([Quirk::Ecn, Quirk::Df, Quirk::NonZeroID]);
    assert_eq!(set.to_string(), "df,id+,ecn");
}

#[test]
fn difference_and_fuzzy_masks() {
    let sig = QuirkSet::from([Quirk::Df, Quirk::NonZeroID]);
    let obs = QuirkSet::from([Quirk::Ecn]);
    let missing = sig.difference(obs);
    let added = obs.difference(sig);
    assert_eq!(missing, QuirkSet::FUZZY_DELETABLE);
    assert!(added.difference(QuirkSet::FUZZY_ADDABLE).is_empty());
    assert!(added.contains(Quirk::Ecn));
}
