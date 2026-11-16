//! The questions a fence holding its service inside the stack lets reach the engine's
//! resolver: one for the address of a service on one of the namespace's networks, which
//! the core hands it. Every other question is answered refused and never passed on, since
//! the engine's resolver forwards a name it does not hold beyond the host. A question
//! passed on is rebuilt from the name it matched, under an id the fence draws, so none of
//! the bits the asker chose ride on to the resolver.

use std::collections::BTreeSet;

/// The setting naming the stack's services a question may ask for.
pub const NAMES: &str = "LEMONFIBER_FENCE_NAMES";

/// How many bytes a DNS message's header holds.
const HEADER: usize = 12;

/// The bit of the header's flags marking a message as an answer.
const ANSWER: u8 = 0x80;

/// The bits of the header's first flag byte naming the operation, and whether recursion
/// was asked for.
const KEPT_FLAGS: u8 = 0x79;

/// The bits of the header's first flag byte naming the operation.
const OPERATION: u8 = 0x78;

/// The bit of the header's first flag byte asking for recursion, the one flag a query
/// passed on carries.
const RECURSION: u8 = 0x01;

/// The answer code for a question the fence will not pass on.
const REFUSED: u8 = 5;

/// The answer code for a question the fence cannot pass on.
const FAILED: u8 = 2;

/// The longest name a question may ask for, in bytes as written on the wire.
const LONGEST_NAME: usize = 255;

/// The count of questions a message asking one, or answering one, carries.
const ONE_QUESTION: [u8; 2] = [0, 1];

/// How many bytes a question's type and class hold.
const TYPED: usize = 4;

/// The type and class a question passed on may ask for: an IPv4 or an IPv6 address, on
/// the internet.
const ASKED: [[u8; TYPED]; 2] = [[0, 1, 0, 1], [0, 28, 0, 1]];

/// How many ids the fence draws for one query before it gives up on an id unlike the
/// asker's.
const DRAWS: usize = 8;

/// What becomes of one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Passed on to the engine's resolver.
    Passed(Passed),
    /// Answered with this message, refused or failed, and never passed on.
    Refused(Vec<u8>),
    /// Not a question at all, and answered with nothing.
    Dropped,
}

/// A question passed on, and what its answer is matched against and given back under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passed {
    /// The query passed on: under an id the fence drew, with only the recursion flag
    /// carried over, asking the one question rebuilt from the name it matched.
    pub query: Vec<u8>,
    /// The id the question was asked under.
    under: [u8; 2],
    /// The question as it was asked.
    asked: Vec<u8>,
}

impl Passed {
    /// The resolver's `answer` as the asker is given it, under the id and the question it
    /// asked with; nothing where it is not an answer to [`Passed::query`].
    #[must_use]
    pub fn answered(&self, answer: &[u8]) -> Option<Vec<u8>> {
        let asked_ends = HEADER + self.asked.len();
        let matches = answer.get(..2) == self.query.get(..2)
            && answer.get(2).is_some_and(|flags| flags & ANSWER != 0)
            && answer.get(4..6) == Some(&ONE_QUESTION)
            && answer.get(HEADER..asked_ends) == self.query.get(HEADER..);
        if !matches {
            return None;
        }
        let mut given = Vec::with_capacity(answer.len());
        given.extend_from_slice(&self.under);
        given.extend_from_slice(answer.get(2..HEADER)?);
        given.extend_from_slice(&self.asked);
        given.extend_from_slice(answer.get(asked_ends..)?);
        Some(given)
    }
}

/// The names the fence is handed, read from `said`: each a service's name, separated by
/// commas or whitespace, without regard to case or a trailing dot.
///
/// # Errors
///
/// Where nothing is said: a fence that does not know the stack's names would refuse every
/// question, so it refuses to start rather than leave the service unable to resolve them.
pub fn names(said: Option<&str>) -> Result<BTreeSet<String>, String> {
    let said = said.ok_or_else(|| {
        format!("{NAMES} is not set, so the names of the stack's services are not known")
    })?;
    Ok(said
        .split(|one: char| one == ',' || one.is_whitespace())
        .map(|one| one.trim_end_matches('.').to_ascii_lowercase())
        .filter(|one| !one.is_empty())
        .collect())
}

/// An id drawn from the system's secure random source; nothing where it cannot be read.
#[must_use]
pub fn drawn() -> Option<u16> {
    let mut id = [0; 2];
    getrandom::getrandom(&mut id).ok()?;
    Some(u16::from_be_bytes(id))
}

/// What becomes of the question `message`, where `names` are the names it may ask for and
/// `draw` draws the id a query passed on is sent under.
#[must_use]
pub fn judged(
    message: &[u8],
    names: &BTreeSet<String>,
    draw: &mut dyn FnMut() -> Option<u16>,
) -> Verdict {
    let (Some(header), Some(section)) = (message.get(..HEADER), message.get(HEADER..)) else {
        return Verdict::Dropped;
    };
    let flags = header.get(2).copied().unwrap_or(ANSWER);
    if flags & ANSWER != 0 {
        return Verdict::Dropped;
    }
    let one_question = header.get(4..6) == Some(&ONE_QUESTION);
    let asked = if one_question && flags & OPERATION == 0 {
        question(section)
    } else {
        None
    };
    let Some((name, asked)) = asked else {
        return Verdict::Refused(refusal(header, &[], REFUSED));
    };
    let typed = asked
        .get(asked.len().saturating_sub(TYPED)..)
        .unwrap_or_default();
    let entry = names.get(&name);
    let Some(entry) = entry.filter(|_| ASKED.iter().any(|one| one.as_slice() == typed)) else {
        return Verdict::Refused(refusal(header, asked, REFUSED));
    };
    let under = [
        header.first().copied().unwrap_or_default(),
        header.get(1).copied().unwrap_or_default(),
    ];
    let unlike = u16::from_be_bytes(under);
    let id = std::iter::repeat_with(draw)
        .take(DRAWS)
        .map_while(std::convert::identity)
        .find(|id| *id != unlike);
    let Some(id) = id else {
        return Verdict::Refused(refusal(header, asked, FAILED));
    };
    Verdict::Passed(Passed {
        query: rebuilt(id, flags & RECURSION, entry, typed),
        under,
        asked: asked.to_vec(),
    })
}

/// The name the question at the start of `section` asks for, lowercase, and the question
/// as written with its type and class; nothing where it is not written whole and plain,
/// with no dot inside a label.
fn question(section: &[u8]) -> Option<(String, &[u8])> {
    let mut labels = Vec::new();
    let mut at = 0;
    loop {
        let length = usize::from(*section.get(at)?);
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        let label = section.get(at + 1..at + 1 + length)?;
        if label.contains(&b'.') {
            return None;
        }
        labels.push(String::from_utf8(label.to_ascii_lowercase()).ok()?);
        at += 1 + length;
        if at > LONGEST_NAME {
            return None;
        }
    }
    let asked = section.get(..at + 1 + TYPED)?;
    Some((labels.join("."), asked))
}

/// The query asking for `name`, the handed entry the question matched, of the type and
/// class `typed`, alone, under `id` with the flags `flags`.
fn rebuilt(id: u16, flags: u8, name: &str, typed: &[u8]) -> Vec<u8> {
    let mut query = Vec::with_capacity(HEADER + name.len() + 2 + TYPED);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[flags, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap_or_default());
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(typed);
    query
}

/// The answer with the code `code` to the question whose header is `header`, holding
/// `asked` as its question where it was read.
fn refusal(header: &[u8], asked: &[u8], code: u8) -> Vec<u8> {
    let mut answer = Vec::with_capacity(HEADER + asked.len());
    answer.extend_from_slice(header.get(..2).unwrap_or_default());
    answer.push(ANSWER | (header.get(2).copied().unwrap_or_default() & KEPT_FLAGS));
    answer.push(code);
    answer.extend_from_slice(&[0, u8::from(!asked.is_empty()), 0, 0, 0, 0, 0, 0]);
    answer.extend_from_slice(asked);
    answer
}

#[cfg(test)]
mod tests;
