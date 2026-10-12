//! Tests for the per-payment stealth scheme representation types.
use pqsa_core::{Error, StealthScheme};
use pqsa_kem::{Kem, MlKem768};
use pqsa_per_payment::{Announcement, EPHEMERAL_PUB_KEY_BYTES, MetaAddress, SchemeId3};

/// Test that MetaAddress and Announcement reject invalid lengths.
#[test]
fn rejects_invalid_lengths() {
    let point = pqsa_ec::public_point(&[0x11; 32]).unwrap();
    for len in [0, MlKem768::EK_BYTES - 1, MlKem768::EK_BYTES + 1] {
        assert_eq!(
            MetaAddress::new(point, point, vec![0xff; len]).unwrap_err(),
            Error::Malformed,
            "encapsulation key {len} B"
        );
    }
    for len in [0, MlKem768::CT_BYTES - 1, MlKem768::CT_BYTES + 1] {
        assert_eq!(
            Announcement::new(point, vec![0xff; len], [0xfe], [0; 20]).unwrap_err(),
            Error::Malformed,
            "ciphertext {len} B"
        );
    }
}

/// Test that serialization and deserialization of MetaAddress and Announcement is consistent.
#[test]
fn serialization_round_trip() {
    let spending = pqsa_ec::public_point(&[0x11; 32]).unwrap();
    let viewing = pqsa_ec::public_point(&[0x22; 32]).unwrap();
    let meta = MetaAddress::new(spending, viewing, vec![0xff; MlKem768::EK_BYTES]).unwrap();
    let wire = SchemeId3::meta_to_bytes(&meta);
    assert_eq!(wire.len(), 66 + MlKem768::EK_BYTES);
    assert_eq!(&wire[..33], spending.as_bytes());
    assert_eq!(&wire[33..66], viewing.as_bytes());
    assert_eq!(&wire[66..], meta.ek());
    let parsed = SchemeId3::meta_from_bytes(&wire).unwrap();
    assert_eq!(SchemeId3::meta_to_bytes(&parsed), wire);
    assert_eq!(SchemeId3::meta_to_bytes(&meta.clone()), wire);
    // Fixed-length keys can still fail ML-KEM validation.
    assert_eq!(
        SchemeId3::announce(&meta, &[0x33; 64]).unwrap_err(),
        Error::Kem
    );

    let ann = Announcement::new(viewing, vec![0xff; MlKem768::CT_BYTES], [0xfe], [0; 20]).unwrap();
    let (address, ephemeral, metadata) = SchemeId3::announcement_to_bytes(&ann);
    assert_eq!(address, [0; 20]);
    assert_eq!(ephemeral.len(), EPHEMERAL_PUB_KEY_BYTES);
    assert_eq!(&ephemeral[..33], viewing.as_bytes());
    assert_eq!(&ephemeral[33..], ann.ct());
    assert_eq!(metadata, [0xfe]);
    let parsed = SchemeId3::announcement_from_bytes(&address, &ephemeral, &metadata).unwrap();
    assert_eq!(
        SchemeId3::announcement_to_bytes(&parsed),
        (address, ephemeral.clone(), metadata.clone())
    );
    assert_eq!(
        SchemeId3::announcement_to_bytes(&ann.clone()),
        (address, ephemeral, metadata)
    );
}
