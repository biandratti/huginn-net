#![cfg(feature = "tcp")]
//! Frozen list of same-tier exact ambiguities in the embedded `p0f.fp`.
//!
//! Selection is first-match-wins within a tier, so these pairs are decided only
//! by `.fp` order. Adding a new pair must fail this test so it gets a look.

use huginn_net_db::tcp::{ambiguous_exact_pairs, AmbiguousExactPair};
use huginn_net_db::TcpDatabase;

fn pair(section: &'static str, winner: &str, shadowed: &str) -> AmbiguousExactPair {
    AmbiguousExactPair {
        section_hint: section,
        winner: winner.to_string(),
        shadowed: shadowed.to_string(),
    }
}

#[test]
fn embedded_p0f_exact_ambiguities_match_the_frozen_list() {
    let db =
        TcpDatabase::load_default().unwrap_or_else(|e| panic!("embedded p0f.fp must parse: {e}"));

    let mut actual = ambiguous_exact_pairs("tcp:request", &db.tcp_request);
    actual.extend(ambiguous_exact_pairs("tcp:response", &db.tcp_response));
    actual.sort();

    let mut expected = vec![
        pair(
            "tcp:request",
            "Generic:win:Windows:NT kernel 5.x :: *:128:0:*:16384,*:mss,nop,nop,sok:df,id+:0",
            "Generic:win:Windows:NT kernel :: *:128:0:*:*,*:mss,nop,nop,sok:df,id+:0",
        ),
        pair(
            "tcp:request",
            "Generic:win:Windows:NT kernel 5.x :: *:128:0:*:16384,*:mss,nop,ws,nop,nop,sok:df,id+:0",
            "Generic:win:Windows:NT kernel :: *:128:0:*:*,*:mss,nop,ws,nop,nop,sok:df,id+:0",
        ),
        pair(
            "tcp:request",
            "Generic:win:Windows:NT kernel 5.x :: *:128:0:*:65535,*:mss,nop,nop,sok:df,id+:0",
            "Generic:win:Windows:NT kernel :: *:128:0:*:*,*:mss,nop,nop,sok:df,id+:0",
        ),
        pair(
            "tcp:request",
            "Generic:win:Windows:NT kernel 5.x :: *:128:0:*:65535,*:mss,nop,ws,nop,nop,sok:df,id+:0",
            "Generic:win:Windows:NT kernel :: *:128:0:*:*,*:mss,nop,ws,nop,nop,sok:df,id+:0",
        ),
        pair(
            "tcp:request",
            "Generic:win:Windows:NT kernel 6.x :: *:128:0:*:8192,*:mss,nop,nop,sok:df,id+:0",
            "Generic:win:Windows:NT kernel :: *:128:0:*:*,*:mss,nop,nop,sok:df,id+:0",
        ),
        pair(
            "tcp:request",
            "Generic:win:Windows:NT kernel 6.x :: *:128:0:*:8192,*:mss,nop,ws,nop,nop,sok:df,id+:0",
            "Generic:win:Windows:NT kernel :: *:128:0:*:*,*:mss,nop,ws,nop,nop,sok:df,id+:0",
        ),
        pair(
            "tcp:response",
            "Specified:unix:FreeBSD:8.x-9.x :: *:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0",
            "Specified:unix:Mac OS X:10.x :: *:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0",
        ),
        pair(
            "tcp:response",
            "Specified:unix:FreeBSD:8.x-9.x :: *:64:0:*:65535,0:mss,sok,eol+1:df,id+:0",
            "Specified:unix:Mac OS X:10.x :: *:64:0:*:65535,0:mss,sok,eol+1:df,id+:0",
        ),
    ];
    expected.sort();

    assert_eq!(
        actual, expected,
        "p0f.fp same-tier exact ambiguities changed; update the frozen list after review"
    );
}
