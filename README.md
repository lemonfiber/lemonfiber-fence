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
connection to loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
`100.64.0.0/10`, `169.254.0.0/16`, multicast, `::1`, `fc00::/7`, `fe80::/10`,
`ff00::/8` and each of the host's own addresses is refused. The engine's resolver
at `127.0.0.11` is let through, so names still resolve, and so are the answers to
connections other services opened. It reads the rules back, reports healthy, and
then holds the namespace. Where any of that fails it exits, so the service behind
it never starts unfenced.

## How the stack runs it

| | |
| --- | --- |
| Settings | `LEMONFIBER_FENCE_HOST_ADDRESSES`: the host's own addresses, separated by commas or spaces, refused beside every private range |
| Privilege | `NET_ADMIN` alone, which lemonfiber grants the fence and never the service behind it |
| Health check | `fence health`, which asks the kernel whether the rules are still in force |
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
