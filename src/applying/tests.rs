use std::cell::RefCell;

use super::{applied, holding, Installed, Nft, Ran};

/// An `nft` answering each call with the next of `answers`, and recording what it was
/// asked.
struct Fake {
    answers: RefCell<Vec<Result<Ran, String>>>,
    asked: RefCell<Vec<(Vec<String>, String)>>,
}

impl Fake {
    fn answering(answers: Vec<Result<Ran, String>>) -> Self {
        Self {
            answers: RefCell::new(answers.into_iter().rev().collect()),
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl Nft for Fake {
    fn run(&self, args: &[&str], input: &str) -> Result<Ran, String> {
        self.asked.borrow_mut().push((
            args.iter().map(|one| (*one).to_owned()).collect(),
            input.to_owned(),
        ));
        self.answers
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| Err("asked once too often".to_owned()))
    }
}

fn ran(succeeded: bool, stdout: &str, stderr: &str) -> Ran {
    Ran {
        succeeded,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    }
}

/// The table as the kernel lists it once the ruleset is in force.
const LISTED: &str = "table inet lemonfiber_fence {
\tset refused_v4 {
\t}
\tset refused_v6 {
\t}
\tchain output {
\t\tip daddr @refused_v4 reject with icmp port-unreachable
\t\tip6 daddr @refused_v6 reject with icmpv6 port-unreachable
\t}
}";

#[test]
fn a_ruleset_is_handed_to_nft_and_read_back_before_it_counts() {
    let nft = Fake::answering(vec![Ok(ran(true, "", "")), Ok(ran(true, LISTED, ""))]);

    assert_eq!(applied(&nft, "the rules"), Ok(()));
    let asked = nft.asked.borrow();
    assert_eq!(
        asked.first(),
        Some(&(
            vec!["-f".to_owned(), "-".to_owned()],
            "the rules".to_owned()
        ))
    );
    assert_eq!(
        asked.get(1).map(|(args, _)| args.join(" ")),
        Some("list table inet lemonfiber_fence".to_owned())
    );
}

#[test]
fn a_ruleset_nft_refused_or_could_not_be_handed_is_not_in_force() {
    let refused = Fake::answering(vec![Ok(ran(false, "", "Error: syntax error\n"))]);
    assert_eq!(
        applied(&refused, "x"),
        Err("nft refused the ruleset: Error: syntax error".to_owned())
    );
    let missing = Fake::answering(vec![Err("nft could not be started: gone".to_owned())]);
    assert_eq!(
        applied(&missing, "x"),
        Err("nft could not be started: gone".to_owned())
    );
}

#[test]
fn a_table_the_kernel_does_not_list_is_not_in_force() {
    let gone = Fake::answering(vec![Ok(ran(false, "", "No such file or directory\n"))]);
    assert_eq!(
        holding(&gone),
        Err("the table lemonfiber_fence is not in force: No such file or directory".to_owned())
    );
    let emptied = Fake::answering(vec![Ok(ran(true, "table inet lemonfiber_fence {\n}", ""))]);
    assert!(holding(&emptied).is_err());
    for missing in [
        "set refused_v4",
        "set refused_v6",
        "chain output",
        "ip daddr @refused_v4 reject",
        "ip6 daddr @refused_v6 reject",
    ] {
        let without = LISTED.replace(missing, "");
        let held = Fake::answering(vec![Ok(ran(true, &without, ""))]);
        assert!(
            holding(&held).is_err_and(|why| why.contains(missing)),
            "a table without {missing} is in force"
        );
    }
    let accepted_then_lost = Fake::answering(vec![Ok(ran(true, "", "")), Ok(ran(false, "", ""))]);
    assert!(applied(&accepted_then_lost, "x").is_err());
}

#[test]
fn a_program_is_handed_its_input_and_answered_with_what_it_printed() {
    let shell = Installed { program: "sh" };
    assert_eq!(
        shell.run(&["-c", "cat; echo said >&2; exit 3"], "the rules"),
        Ok(ran(false, "the rules", "said\n"))
    );
    let absent = Installed {
        program: "lemonfiber-fence-no-such-program",
    };
    assert!(absent
        .run(&[], "")
        .is_err_and(|why| why.starts_with("lemonfiber-fence-no-such-program could not be run:")));
}
