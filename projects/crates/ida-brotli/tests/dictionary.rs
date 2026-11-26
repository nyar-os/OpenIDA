//! Integration tests for the RFC 7932 static dictionary word transforms.

use ida_brotli::{apply_transform, word};

#[test]
fn identity_transform_keeps_the_word() {
    assert_eq!(apply_transform(0, b"time").unwrap(), b"time");
}

#[test]
fn suffix_transform_appends_a_space() {
    assert_eq!(apply_transform(1, b"time").unwrap(), b"time ");
}

#[test]
fn uppercase_first_transform() {
    assert_eq!(apply_transform(4, b"time").unwrap(), b"Time ");
}

#[test]
fn omit_first_and_last_transforms() {
    assert_eq!(apply_transform(3, b"time").unwrap(), b"ime");
    assert_eq!(apply_transform(12, b"time").unwrap(), b"tim");
}

#[test]
fn dictionary_lookup_of_the_first_word() {
    assert_eq!(word(4, 0).unwrap(), b"time");
}

#[test]
fn dictionary_rejects_unknown_lengths() {
    assert!(word(3, 0).is_err());
    assert!(word(25, 0).is_err());
}
