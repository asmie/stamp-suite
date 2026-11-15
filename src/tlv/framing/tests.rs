use super::*;
use proptest::prelude::*;

const CONTAINERS: [(u8, usize); 5] = [(2, 4), (3, 4), (10, 0), (12, 8), (243, 8)];

fn frame(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, kind];
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

#[test]
fn walker_reports_one_failure_and_is_fused() {
    let bytes = [0xff, 250, 0, 0, 0x80, 251, 0, 5, 1, 2];
    let mut frames = TlvFrames::new(&bytes, 0);
    let first = frames.next().unwrap().unwrap();
    assert_eq!(
        (first.start, first.end(), first.tlv_type.to_byte()),
        (0, 4, 250)
    );
    assert_eq!(
        frames.next(),
        Some(Err(TlvFramingError {
            offset: 4,
            parent: None,
            kind: TlvFramingErrorKind::IncompleteValue {
                declared: 5,
                available: 2
            },
        }))
    );
    assert_eq!(frames.next(), None);
    assert_eq!(frames.next(), None);
}

#[test]
fn short_outer_headers_and_extreme_start_offsets_are_bounded() {
    assert_eq!(check_tlv_framing(&[]), Ok(()));
    for available in 1..4 {
        let bytes = vec![0; available];
        assert_eq!(
            check_tlv_framing(&bytes),
            Err(TlvFramingError {
                offset: 0,
                parent: None,
                kind: TlvFramingErrorKind::IncompleteHeader { available },
            })
        );
        assert_eq!(TlvFrames::new(&bytes, usize::MAX).next(), None);
        assert_eq!(TlvFrames::new(&bytes, bytes.len()).next(), None);
    }
}

#[test]
fn known_children_report_absolute_offsets_and_parent_ownership() {
    let leading = frame(1, &[0xaa]);
    for (kind, prefix) in CONTAINERS {
        for flags in [0, 0x80, 0x40, 0x20, 0x10, 0xff] {
            for tail in [&[0x80][..], &[0x80, 250, 0][..], &[0x80, 250, 0, 5, 1][..]] {
                let mut value = vec![0; prefix];
                value.extend_from_slice(&frame(250, &[9]));
                let offset = leading.len() + 4 + value.len();
                value.extend_from_slice(tail);
                let mut parent = frame(kind, &value);
                parent[0] = flags;
                let bytes = [&leading[..], &parent].concat();
                let error = check_tlv_framing(&bytes).unwrap_err();
                assert_eq!(error.offset, offset);
                assert_eq!(error.parent, Some(leading.len()));
                assert_eq!(
                    error.kind,
                    if tail.len() < 4 {
                        TlvFramingErrorKind::IncompleteHeader {
                            available: tail.len(),
                        }
                    } else {
                        TlvFramingErrorKind::IncompleteValue {
                            declared: 5,
                            available: 1,
                        }
                    }
                );
            }
        }
    }
}

#[test]
fn child_values_cannot_consume_a_later_parent() {
    for (kind, prefix) in CONTAINERS {
        let mut value = vec![0; prefix];
        value.extend_from_slice(&[0x80, 250, 0, 4]);
        let mut bytes = frame(kind, &value);
        bytes.extend_from_slice(&frame(1, &[8; 8]));
        assert_eq!(
            check_tlv_framing(&bytes),
            Err(TlvFramingError {
                offset: 4 + prefix,
                parent: Some(0),
                kind: TlvFramingErrorKind::IncompleteValue {
                    declared: 4,
                    available: 0
                },
            })
        );
    }
}

#[test]
fn incomplete_parent_takes_precedence_over_apparent_children() {
    let bytes = [0x80, 10, 0, 20, 0x80, 250, 0, 4];
    assert_eq!(
        check_tlv_framing(&bytes),
        Err(TlvFramingError {
            offset: 0,
            parent: None,
            kind: TlvFramingErrorKind::IncompleteValue {
                declared: 20,
                available: 4
            },
        })
    );
}

#[test]
fn framing_success_does_not_validate_semantic_lengths_or_integrity() {
    for (kind, prefix) in CONTAINERS {
        for size in 0..prefix {
            // Complete outer values without their fixed prefix remain semantic
            // errors; callers retain the existing M response path.
            assert_eq!(check_tlv_framing(&frame(kind, &vec![0xff; size])), Ok(()));
        }
    }
    // A short, but completely framed, BER pattern remains a semantic M case.
    let mut ber = vec![0; 8];
    ber.extend_from_slice(&frame(241, &[1, 2, 3]));
    assert_eq!(check_tlv_framing(&frame(243, &ber)), Ok(()));
    // Duplicate/short HMAC values and illegal placement belong to integrity
    // policy. A framing-only checker cannot declare their digests valid.
    let bytes = [frame(8, &[0; 3]), frame(8, &[]), frame(250, &[1])].concat();
    assert_eq!(check_tlv_framing(&bytes), Ok(()));
}

#[test]
fn maximum_values_and_many_zero_length_frames_make_progress() {
    assert_eq!(
        check_tlv_framing(&frame(1, &vec![0; usize::from(u16::MAX)])),
        Ok(())
    );
    let bytes = [0, 250, 0, 0].repeat(16_384);
    assert_eq!(TlvFrames::new(&bytes, 0).count(), 16_384);
    assert_eq!(check_tlv_framing(&bytes), Ok(()));
    assert_eq!(
        check_tlv_framing(&[0, 1, 255, 255]),
        Err(TlvFramingError {
            offset: 0,
            parent: None,
            kind: TlvFramingErrorKind::IncompleteValue {
                declared: 65_535,
                available: 0
            },
        })
    );
}

proptest! {
    #[test]
    fn hand_encoded_frames_match_offsets_values_and_trailing_fragments(
        leading in proptest::collection::vec(any::<u8>(), 0..24),
        entries in proptest::collection::vec((any::<u8>(), any::<u8>(), proptest::collection::vec(any::<u8>(), 0..64)), 0..40),
        tail in proptest::collection::vec(any::<u8>(), 0..4),
    ) {
        let mut bytes = leading.clone();
        let mut expected = Vec::new();
        for (flags, kind, value) in &entries {
            let start = bytes.len();
            let mut encoded = frame(*kind, value);
            encoded[0] = *flags;
            bytes.extend_from_slice(&encoded);
            expected.push((start, bytes.len(), *flags, *kind, value));
        }
        let tail_at = bytes.len();
        bytes.extend_from_slice(&tail);
        let mut actual = TlvFrames::new(&bytes, leading.len());
        for (start, end, flags, kind, value) in expected {
            let span = actual.next().unwrap().unwrap();
            prop_assert_eq!((span.start, span.end()), (start, end));
            prop_assert_eq!(span.tlv_type.to_byte(), kind);
            prop_assert_eq!(span.flags.to_byte(), flags & 0xf0);
            prop_assert_eq!(&bytes[span.value()], value.as_slice());
        }
        if !tail.is_empty() {
            prop_assert_eq!(actual.next(), Some(Err(TlvFramingError {
                offset: tail_at, parent: None,
                kind: TlvFramingErrorKind::IncompleteHeader { available: tail.len() },
            })));
        }
        prop_assert_eq!(actual.next(), None);
        prop_assert_eq!(actual.next(), None);
    }

    #[test]
    fn opaque_values_and_child_type_numbers_never_trigger_recursion(
        value in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        for opaque in [1, 8, 247, 250, 254] {
            prop_assert_eq!(check_tlv_framing(&frame(opaque, &value)), Ok(()));
        }
        for (parent, prefix) in CONTAINERS {
            for (child, _) in CONTAINERS {
                let mut body = vec![0; prefix];
                body.extend_from_slice(&frame(child, &value));
                prop_assert_eq!(check_tlv_framing(&frame(parent, &body)), Ok(()));
            }
        }
    }
}
