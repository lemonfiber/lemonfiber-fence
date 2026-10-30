# lemonfiber-fence

The fence is a small container inside a [lemonfiber](https://github.com/lemonfiber/lemonfiber)
media stack. It stands beside a service that fetches whatever address it is
handed, such as a challenge solver driving a browser to the page an indexer sits
behind, and keeps that service off every private address: the machine itself,
the home network, the other services of the stack and a cloud's metadata
address.

This repository builds the container image `ghcr.io/lemonfiber/fence`. You do not
run it yourself: lemonfiber writes a fence beside each service that declares
`network = { fenced = true }`, and the bundle pins the image.

## Why it exists

A service told to fetch one address can be led to another. A browser follows
redirects and loads whatever a page names, so checking the first address is not
enough. The fence refuses the connection itself, in the network namespace the
service runs in, whatever led the service there.

## What it does

At start it installs nftables rules in the namespace it holds. Every new
connection is refused to each range the core's own check on a name refuses
(loopback, the private and carrier-grade NAT ranges, link-local and metadata,
documentation, benchmarking, multicast and reserved, IPv6 unique-local,
link-local and site-local), to every IPv6 range whose addresses carry an IPv4 one
(mapped, compatible, NAT64, 6to4 and Teredo), and to each of the host's own
addresses. The ranges are read from the core's `lemonfiber-outward`, so the two
cannot disagree. The engine's resolver at `127.0.0.11` is let through on port 53
alone, so names still resolve, and so are the answers to connections other
services opened. It reads the rules back, reports healthy, and then holds the
namespace. Where any of that fails, or it is handed no host address, it exits, so
the service behind it never starts unfenced.

## How the stack runs it

| | |
| --- | --- |
| Settings | `LEMONFIBER_FENCE_HOST_ADDRESSES`: the host's own addresses, separated by commas or spaces, refused beside every private range. Required: the fence refuses to start without at least one |
| Privilege | `NET_ADMIN` alone, which lemonfiber grants the fence and never the service behind it |
| Health check | `fence health`, which asks the kernel whether the table, both its sets, its chain and the rules refusing each set are still in force |
| The service behind it | Written into the fence's network namespace, started once the fence is healthy, and restarted with it |

## Building and testing

You need Rust (the version in [`rust-toolchain.toml`](rust-toolchain.toml)) and
Docker.

```sh
cargo test
docker build -t fence .
```

Images are published on the release train, and the bundle pins the digest each
tag published.
