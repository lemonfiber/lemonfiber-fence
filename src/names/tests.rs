use std::collections::BTreeSet;

use super::{judged, names, Passed, Verdict};

/// The id every query passed on is drawn as in these tests, unlike any the tests ask under.
const DRAWN: u16 = 0x5a5a;

/// A query with the id `id` and the first flag byte `flags`, asking for `name` with the
/// type and class `typed`.
fn query(id: u16, flags: u8, name: &str, typed: [u8; 4]) -> Vec<u8> {
    let mut message = id.to_be_bytes().to_vec();
    message.extend_from_slice(&[flags, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        message.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&typed);
    message
}

/// A query with the id `0x1234` asking recursively for the IPv4 address of `name`.
fn asking(name: &str) -> Vec<u8> {
    query(0x1234, 0x01, name, [0, 1, 0, 1])
}

/// `query` as the fence passes it on, under [`DRAWN`].
fn forwarded(name: &str) -> Vec<u8> {
    query(DRAWN, 0x01, name, [0, 1, 0, 1])
}

fn stack() -> BTreeSet<String> {
    names(Some("sonarr, Radarr.\nprowlarr")).unwrap_or_default()
}

fn judging(message: &[u8]) -> Verdict {
    judged(message, &stack(), &mut || Some(DRAWN))
}

/// The query `verdict` passes on, or nothing where it refuses or drops the question.
fn passed(verdict: Verdict) -> Option<Passed> {
    match verdict {
        Verdict::Passed(passed) => Some(passed),
        Verdict::Refused(_) | Verdict::Dropped => None,
    }
}

/// The refusal `verdict` answers with, or nothing where it passes or drops the question.
fn refusal(verdict: Verdict) -> Option<Vec<u8>> {
    match verdict {
        Verdict::Refused(answer) => Some(answer),
        Verdict::Passed(_) | Verdict::Dropped => None,
    }
}

/// `message` with its byte at `at` changed by `change`.
fn altered(mut message: Vec<u8>, at: usize, change: impl Fn(u8) -> u8) -> Vec<u8> {
    if let Some(byte) = message.get_mut(at) {
        *byte = change(*byte);
    }
    message
}

/// `query` as a resolver answers it: marked an answer, recursion available, one address
/// record pointing back at the question's name.
fn resolved(query: &[u8]) -> Vec<u8> {
    let mut answer = altered(altered(query.to_vec(), 2, |flags| flags | 0x80), 3, |_| {
        0x80
    });
    answer = altered(answer, 7, |_| 1);
    answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 172, 18, 0, 5]);
    answer
}

#[test]
fn names_are_read_past_commas_whitespace_case_and_a_trailing_dot() {
    assert_eq!(
        stack(),
        BTreeSet::from([
            "sonarr".to_owned(),
            "radarr".to_owned(),
            "prowlarr".to_owned()
        ])
    );
    assert_eq!(
        names(None),
        Err(
            "LEMONFIBER_FENCE_NAMES is not set, so the names of the stack's services are not known"
                .to_owned()
        )
    );
}

#[test]
fn a_question_for_a_stack_service_is_passed_on_lowercased_whatever_its_case() {
    let sonarr = passed(judging(&asking("sonarr")));
    assert_eq!(sonarr.map(|one| one.query), Some(forwarded("sonarr")));
    let mixed = passed(judging(&asking("RaDaRR")));
    assert_eq!(mixed.map(|one| one.query), Some(forwarded("radarr")));
    let ipv6 = passed(judging(&query(0x1234, 0x01, "Sonarr", [0, 28, 0, 1])));
    assert_eq!(
        ipv6.map(|one| one.query),
        Some(query(DRAWN, 0x01, "sonarr", [0, 28, 0, 1]))
    );
}

#[test]
fn an_answer_is_given_back_under_the_id_and_question_asked() {
    let asked = asking("RaDaRR");
    let passing = passed(judging(&asked));
    assert!(passing.is_some(), "a stack name is passed on");
    let Some(passing) = passing else {
        return;
    };
    let given = passing.answered(&resolved(&passing.query));
    assert_eq!(given, Some(resolved(&asked)));
    assert_eq!(passing.answered(&passing.query), None, "not an answer");
    let other = altered(resolved(&passing.query), 1, |id| id ^ 1);
    assert_eq!(passing.answered(&other), None, "another id");
    let elsewhere = resolved(&forwarded("sonarr"));
    assert_eq!(passing.answered(&elsewhere), None, "another question");
    let cut = resolved(&passing.query);
    assert_eq!(passing.answered(cut.get(..14).unwrap_or_default()), None);
}

/// A generator of ids from a fixed seed, so the run is the same each time.
fn seeded(mut state: u32) -> impl FnMut() -> Option<u16> {
    move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        u16::try_from(state >> 16).ok()
    }
}

#[test]
fn the_id_passed_on_is_never_the_one_asked_under_and_is_mapped_back() {
    let mut draw = seeded(0x9e37_79b9);
    for asker in (0..=u16::MAX).step_by(97) {
        let asked = query(asker, 0x01, "prowlarr", [0, 1, 0, 1]);
        let passing = passed(judged(&asked, &stack(), &mut draw));
        assert!(passing.is_some(), "a stack name is passed on");
        let Some(passing) = passing else {
            return;
        };
        assert_ne!(passing.query.get(..2), asked.get(..2));
        let given = passing.answered(&resolved(&passing.query));
        assert_eq!(given, Some(resolved(&asked)));
    }
    let mut draws = [Some(0x1234), Some(0x4321)].into_iter();
    let redrawn = passed(judged(&asking("sonarr"), &stack(), &mut || {
        draws.next().flatten()
    }));
    assert_eq!(
        redrawn.and_then(|one| one.query.get(..2).map(<[u8]>::to_vec)),
        Some(vec![0x43, 0x21])
    );
    let failed = refusal(judged(&asking("sonarr"), &stack(), &mut || None));
    assert_eq!(failed.and_then(|answer| answer.get(3).copied()), Some(2));
    let same = refusal(judged(&asking("sonarr"), &stack(), &mut || Some(0x1234)));
    assert_eq!(same.and_then(|answer| answer.get(3).copied()), Some(2));
}

#[test]
fn only_the_recursion_flag_rides_on() {
    let flagged = altered(query(0x1234, 0x07, "sonarr", [0, 1, 0, 1]), 3, |_| 0x70);
    let passing = passed(judging(&flagged));
    assert_eq!(passing.map(|one| one.query), Some(forwarded("sonarr")));
    let unrecursed = passed(judging(&query(0x1234, 0x00, "sonarr", [0, 1, 0, 1])));
    assert_eq!(
        unrecursed.map(|one| one.query),
        Some(query(DRAWN, 0x00, "sonarr", [0, 1, 0, 1]))
    );
}

#[test]
fn a_question_for_anything_but_an_internet_address_is_refused() {
    for typed in [
        [0, 16, 0, 1],
        [0, 255, 0, 1],
        [0, 1, 0, 3],
        [0, 1, 0, 255],
        [1, 1, 0, 1],
    ] {
        let asked = query(0x1234, 0x01, "sonarr", typed);
        let answer = refusal(judging(&asked)).unwrap_or_default();
        assert_eq!(answer.get(..4), Some([0x12, 0x34, 0x81, 0x05].as_slice()));
        assert_eq!(answer.get(12..), asked.get(12..));
    }
}

#[test]
fn a_question_for_any_other_name_is_refused_and_never_passed_on() {
    let asked = asking("leaked-bits.example.com");
    let answer = refusal(judging(&asked)).unwrap_or_default();
    assert_eq!(answer.get(..4), Some([0x12, 0x34, 0x81, 0x05].as_slice()));
    assert_eq!(answer.get(4..12), Some([0, 1, 0, 0, 0, 0, 0, 0].as_slice()));
    assert_eq!(answer.get(12..), asked.get(12..));
    assert!(refusal(judging(&asking("sonarr.example.com"))).is_some());
}

#[test]
fn a_message_that_is_not_one_plain_question_is_refused_or_dropped() {
    let two = altered(asking("sonarr"), 5, |_| 2);
    assert_eq!(
        refusal(judging(&two)).and_then(|answer| answer.get(5).copied()),
        Some(0)
    );
    let notify = altered(asking("sonarr"), 2, |_| 0x20);
    assert!(refusal(judging(&notify)).is_some());
    let compressed = altered(asking("sonarr"), 12, |_| 0xc0);
    assert!(refusal(judging(&compressed)).is_some());
    let answer = altered(asking("sonarr"), 2, |flags| flags | 0x80);
    assert_eq!(judging(&answer), Verdict::Dropped);
    assert_eq!(judging(&[0x12, 0x34]), Verdict::Dropped);
    let label = "a".repeat(63);
    let long = asking(&[label.as_str(); 5].join("."));
    assert!(refusal(judging(&long)).is_some_and(|answer| answer.get(5) == Some(&0)));
    let oversized = asking(&"b".repeat(64));
    assert!(refusal(judging(&oversized)).is_some());
    let truncated = asking("sonarr");
    let cut = truncated.get(..truncated.len() - 2).unwrap_or_default();
    assert!(refusal(judging(cut)).is_some());
    let dotted = names(Some("sonarr.lan")).unwrap_or_default();
    let one_label = altered(asking("sonarr-lan"), 19, |_| b'.');
    assert!(refusal(judged(&one_label, &dotted, &mut || Some(DRAWN))).is_some());
    assert!(passed(judged(&asking("sonarr.lan"), &dotted, &mut || Some(DRAWN))).is_some());
}

/// Whatever is sent beside the one question, records or bytes, is never passed on: the
/// query passed is rebuilt from the name matched alone.
#[test]
fn only_the_question_read_is_passed_on_whatever_rides_beside_it() {
    let mut additional = altered(asking("sonarr"), 11, |_| 1);
    additional.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 60, 0, 4, b'l', b'e', b'a', b'k']);
    let mut trailing = asking("sonarr");
    trailing.extend_from_slice(b"exfiltrated bytes");
    let answering = altered(altered(asking("sonarr"), 7, |_| 3), 9, |_| 2);
    for asked in [additional, trailing, answering] {
        let passing = passed(judging(&asked));
        assert_eq!(passing.map(|one| one.query), Some(forwarded("sonarr")));
    }
}
