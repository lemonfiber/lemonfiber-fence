# AGENTS.md — lemonfiber-fence

> **Start at the roadmap and board on [lemonfiber.app](https://lemonfiber.app),
> rendered from the report of where every unreleased version stands. Then the
> rules** every repository shares:
> [working in the repositories](https://github.com/lemonfiber/spec/blob/main/50-governance/working-in-the-repositories.md)
> and [the rules for agents](https://github.com/lemonfiber/spec/blob/main/50-governance/ai-contributors.md).
> This file holds only what is true of this repository.

## What this repo is

The fence: the container lemonfiber writes beside a service that fetches whatever address it is handed, holding that service's network namespace to rules refusing every private address. One Rust binary crate and one image carrying it, nftables and tini. See the spec:
[`30-repos/lemonfiber-fence.md`](https://github.com/lemonfiber/spec/blob/main/30-repos/lemonfiber-fence.md).

## The one rule you cannot break here

**The fence fails closed.** It reports healthy only once the kernel lists its table, and exits where the rules cannot be installed or a host address it is handed cannot be read, so the service behind it never starts in a namespace the rules do not hold. A ruleset that lets a new connection through to loopback, a private, carrier-grade NAT, link-local, metadata, multicast or unique-local address, or to a host address it was handed, is a defect however it is reached. The engine's resolver and the answers to connections others opened are the only things let through to such an address.

## Code standards (enforced)

- `unsafe` is **forbidden**. No `unwrap`/`expect`/`panic`/`todo` in non-test code.
- **No lint suppressions in `src/`**: change the code or the rule, never `#[allow]`.
- The ranges the fence refuses are this image's alone. Nothing a manifest says widens or narrows them.
- Every line outside `main.rs` is covered by a test.
