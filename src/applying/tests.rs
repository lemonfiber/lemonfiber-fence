use std::cell::RefCell;

use super::{applied, holding, holding_either, probed, Held, Installed, Nft, Ran};
use crate::rules::{ruleset, PROBE, TABLE};

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

    assert_eq!(applied(&nft, TABLE, "the rules", Held::Refusing), Ok(()));
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
        applied(&refused, TABLE, "x", Held::Refusing),
        Err("nft refused the ruleset: Error: syntax error".to_owned())
    );
    let missing = Fake::answering(vec![Err("nft could not be started: gone".to_owned())]);
    assert_eq!(
        applied(&missing, TABLE, "x", Held::Refusing),
        Err("nft could not be started: gone".to_owned())
    );
}

#[test]
fn a_table_the_kernel_does_not_list_is_not_in_force() {
    let gone = Fake::answering(vec![Ok(ran(false, "", "No such file or directory\n"))]);
    assert_eq!(
        holding(&gone, TABLE, Held::Refusing),
        Err("the table lemonfiber_fence is not in force: No such file or directory".to_owned())
    );
    let emptied = Fake::answering(vec![Ok(ran(true, "table inet lemonfiber_fence {\n}", ""))]);
    assert!(holding(&emptied, TABLE, Held::Refusing).is_err());
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
            holding(&held, TABLE, Held::Refusing).is_err_and(|why| why.contains(missing)),
            "a table without {missing} is in force"
        );
    }
    let accepted_then_lost = Fake::answering(vec![Ok(ran(true, "", "")), Ok(ran(false, "", ""))]);
    assert!(applied(&accepted_then_lost, TABLE, "x", Held::Refusing).is_err());
}

/// Asking whether a namespace can hold the rules puts the fence's own ruleset in place
/// under a table of its own, reads it back, and takes it away again.
#[test]
fn the_probe_installs_the_fences_rules_reads_them_back_and_takes_them_away() {
    let nft = Fake::answering(vec![
        Ok(ran(true, "", "")),
        Ok(ran(true, LISTED, "")),
        Ok(ran(true, "", "")),
    ]);

    assert_eq!(probed(&nft), Ok(()));
    let asked = nft.asked.borrow();
    let args: Vec<String> = asked.iter().map(|(args, _)| args.join(" ")).collect();
    assert_eq!(
        args,
        [
            "-f -".to_owned(),
            format!("list table inet {PROBE}"),
            format!("delete table inet {PROBE}"),
        ]
    );
    assert_eq!(
        asked.first().map(|(_, input)| input.clone()),
        Some(ruleset(PROBE, &[]))
    );
}

/// A namespace whose kernel refuses the rules, does not list what it accepted, or keeps
/// the table once asked to take it away, cannot hold a fence, and says why.
#[test]
fn a_namespace_that_cannot_hold_the_rules_says_why() {
    let refused = Fake::answering(vec![Ok(ran(
        false,
        "",
        "Error: Could not process rule: Operation not permitted\n",
    ))]);
    assert_eq!(
        probed(&refused),
        Err(
            "nft refused the ruleset: Error: Could not process rule: Operation not permitted"
                .to_owned()
        )
    );
    let unlisted = Fake::answering(vec![Ok(ran(true, "", "")), Ok(ran(false, "", "gone\n"))]);
    assert_eq!(
        probed(&unlisted),
        Err(format!("the table {PROBE} is not in force: gone"))
    );
    let kept = Fake::answering(vec![
        Ok(ran(true, "", "")),
        Ok(ran(true, LISTED, "")),
        Ok(ran(false, "", "Error: busy\n")),
    ]);
    assert_eq!(
        probed(&kept),
        Err(format!(
            "the table {PROBE} could not be taken away again: Error: busy"
        ))
    );
    let untaken = Fake::answering(vec![
        Ok(ran(true, "", "")),
        Ok(ran(true, LISTED, "")),
        Err("nft could not be run: gone".to_owned()),
    ]);
    assert_eq!(
        probed(&untaken),
        Err("nft could not be run: gone".to_owned())
    );
    let missing = Fake::answering(vec![Err("nft could not be run: gone".to_owned())]);
    assert_eq!(
        probed(&missing),
        Err("nft could not be run: gone".to_owned())
    );
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

/// A fence holding its service inside the stack is in force only while the kernel lists
/// every set and rule of that ruleset, and the other ruleset's do not stand in for them.
#[test]
fn a_table_holding_a_service_inside_the_stack_is_in_force_only_with_its_own_rules() {
    let inside = [
        "set inside_v4",
        "set inside_v6",
        "set barred_v4",
        "set barred_v6",
        "chain output",
        "ip daddr @barred_v4 reject",
        "ip6 daddr @barred_v6 reject",
        "ip daddr @inside_v4 accept",
        "ip6 daddr @inside_v6 accept",
        "chain resolving",
        "udp dport 53 redirect to :53530",
        "tcp dport 53 redirect to :53530",
    ];
    let listed = inside.join("\n");
    let held = Fake::answering(vec![Ok(ran(true, &listed, ""))]);
    assert_eq!(holding(&held, TABLE, Held::Inside), Ok(()));
    let refusing = Fake::answering(vec![Ok(ran(true, LISTED, ""))]);
    assert!(holding(&refusing, TABLE, Held::Inside).is_err());
    for missing in inside {
        let without = listed.replace(missing, "");
        let held = Fake::answering(vec![Ok(ran(true, &without, ""))]);
        assert!(
            holding(&held, TABLE, Held::Inside).is_err_and(|why| why.contains(missing)),
            "a table without {missing} is in force"
        );
    }
}

/// The health check holds either ruleset whole to be in force, so one image answers for a
/// fenced service and a service held inside the stack, and a table holding half of each
/// is not in force.
#[test]
fn health_holds_either_ruleset_whole() {
    let refusing = Fake::answering(vec![Ok(ran(true, LISTED, ""))]);
    assert_eq!(holding_either(&refusing, TABLE), Ok(()));
    let inside = Fake::answering(vec![Ok(ran(
        true,
        "set inside_v4 set inside_v6 set barred_v4 set barred_v6 chain output \
         ip daddr @barred_v4 reject ip6 daddr @barred_v6 reject ip daddr @inside_v4 accept \
         ip6 daddr @inside_v6 accept chain resolving udp dport 53 redirect to :53530 \
         tcp dport 53 redirect to :53530",
        "",
    ))]);
    assert_eq!(holding_either(&inside, TABLE), Ok(()));
    let halves = Fake::answering(vec![Ok(ran(
        true,
        "set refused_v4 set inside_v4 chain output",
        "",
    ))]);
    assert_eq!(
        holding_either(&halves, TABLE),
        Err(
            "the table lemonfiber_fence holds neither ruleset whole: it lacks set refused_v6 to \
             refuse every private address, and set inside_v6 to hold its service inside the stack"
                .to_owned()
        )
    );
    let gone = Fake::answering(vec![Ok(ran(false, "", "No such file or directory\n"))]);
    assert!(holding_either(&gone, TABLE).is_err());
}
