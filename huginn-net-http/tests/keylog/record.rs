use super::vectors::{RFC8448_C_AP_SECRET, RFC8448_C_HS_SECRET, hex};
use huginn_net_http::keylog_internals::{
    CT_APPLICATION_DATA, CT_HANDSHAKE, CipherSuite, RawRecord, RecordDecryptor, RecordError,
    split_records, tls13_traffic_keys,
};

fn rfc8448_decryptor(secret: &str) -> RecordDecryptor {
    let Some(suite) = CipherSuite::from_id(0x1301) else {
        panic!("0x1301 must be supported");
    };
    let keys = match tls13_traffic_keys(&hex(secret), suite) {
        Ok(k) => k,
        Err(_) => panic!("derivation must succeed"),
    };
    match RecordDecryptor::new(suite, &keys) {
        Ok(d) => d,
        Err(e) => panic!("decryptor must build: {e:?}"),
    }
}

fn single_record(bytes: &[u8]) -> RawRecord {
    match split_records(bytes) {
        Ok((mut records, used)) if records.len() == 1 && used == bytes.len() => records.remove(0),
        other => panic!("expected exactly one complete record, got {other:?}"),
    }
}

// RFC 8448 section 3: "{client} send handshake record" (the client Finished), 58 octets.
const RFC8448_CLIENT_FINISHED_RECORD: &str = "17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 46";
// RFC 8448 section 3: "{client} send application_data record", 72 octets.
const RFC8448_CLIENT_APP_RECORD: &str = "17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4";

#[test]
fn rfc8448_client_finished_record() {
    let mut dec = rfc8448_decryptor(RFC8448_C_HS_SECRET);
    let record = single_record(&hex(RFC8448_CLIENT_FINISHED_RECORD));
    let (ct, plain) = match dec.open(&record) {
        Ok(r) => r,
        Err(e) => panic!("must decrypt: {e:?}"),
    };
    assert_eq!(ct, CT_HANDSHAKE);
    assert_eq!(
        plain.as_slice(),
        hex(
            "14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61"
        )
    );
}

#[test]
fn rfc8448_client_application_record() {
    let mut dec = rfc8448_decryptor(RFC8448_C_AP_SECRET);
    let record = single_record(&hex(RFC8448_CLIENT_APP_RECORD));
    let (ct, plain) = match dec.open(&record) {
        Ok(r) => r,
        Err(e) => panic!("must decrypt: {e:?}"),
    };
    assert_eq!(ct, CT_APPLICATION_DATA);
    let expected: Vec<u8> = (0u8..50).collect();
    assert_eq!(plain.as_slice(), expected.as_slice());
}

#[test]
fn flipped_bit_fails_authentication_and_keeps_seq() {
    let mut dec = rfc8448_decryptor(RFC8448_C_AP_SECRET);
    let mut bytes = hex(RFC8448_CLIENT_APP_RECORD);
    bytes[10] ^= 0x01;
    assert_eq!(dec.open(&single_record(&bytes)).err(), Some(RecordError::Auth));
    // seq did not advance: the untampered record still decrypts at seq 0.
    assert!(
        dec.open(&single_record(&hex(RFC8448_CLIENT_APP_RECORD)))
            .is_ok()
    );
}

#[test]
fn wrong_sequence_number_fails_authentication() {
    let mut dec = rfc8448_decryptor(RFC8448_C_AP_SECRET).with_seq(1);
    assert_eq!(
        dec.open(&single_record(&hex(RFC8448_CLIENT_APP_RECORD)))
            .err(),
        Some(RecordError::Auth)
    );
}

#[test]
fn split_records_keeps_partial_tail_and_rejects_oversized() {
    let full = hex(RFC8448_CLIENT_APP_RECORD);
    let mut buf = full.clone();
    buf.extend_from_slice(&full[..10]);
    match split_records(&buf) {
        Ok((records, used)) => {
            assert_eq!(records.len(), 1);
            assert_eq!(used, full.len());
        }
        Err(e) => panic!("must split: {e:?}"),
    }
    assert_eq!(
        split_records(&[0x17, 0x03, 0x03, 0xFF, 0xFF]).err(),
        Some(RecordError::Malformed)
    );
}

#[test]
fn suite_table() {
    for id in [
        0x1301u16, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009C, 0x009E, 0xC02C, 0xC030, 0x009D, 0x009F,
        0xCCA8, 0xCCA9, 0xCCAA,
    ] {
        assert!(CipherSuite::from_id(id).is_some(), "{id:#06x} must be supported");
    }
    for id in [0x002Fu16, 0x0035, 0xC013, 0x00FF] {
        assert!(CipherSuite::from_id(id).is_none(), "{id:#06x} must be unsupported");
    }
}
