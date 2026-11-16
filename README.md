# lemonfiber-fence

The fence is a small container inside a [lemonfiber](https://github.com/lemonfiber/lemonfiber)
media stack. It stands beside a service that fetches whatever address it is
handed, such as a challenge solver driving a browser to the page an indexer sits
behind, and keeps that service off every private address: the machine itself,
the home network, the other services of the stack and a cloud's metadata
address.

This repository builds the container image `ghcr.io/lemonfiber/fence`. You do not
run it yourself: lemonfiber writes a fence beside each service that declares
`network = { fenced = true }`, and beside each service held inside the stack by
`network = { internal = true }`, and the bundle pins the image.

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
(mapped, compatible, NAT64, 6to4 and Teredo), to each of the host's own
addresses, and to every address the namespace's own routes class as broadcast,
multicast or anycast. The ranges are read from the core's `lemonfiber-outward`, so the two
cannot disagree. A connection on the namespace's own loopback interface to any
address but the resolver's is let through, since it reaches nothing outside the
namespace, so a service whose parts talk to each other over it still runs. The
engine's resolver at `127.0.0.11` is let through on port 53 alone, so names still
resolve, and so are the answers to connections other services opened. It reads
the rules back, reports healthy, and then holds the namespace. Where any of that
fails, or it is handed no host address, it exits, so the service behind it never
starts unfenced.

Run as `fence stack`, beside a service held inside the stack, it holds the opposite
rules. A new connection passes only to an address inside the subnet of one of the
namespace's own networks that is neither that network's gateway, its own address, its
IPv4 broadcast address, one of the host's addresses nor an address the namespace's own
routes class as broadcast, multicast or anycast, out of the namespace's own loopback interface to any address but the
resolver's, and to the resolver on port 53, and every other is refused, so the service
reaches the stack's services and resolves their names, and reaches neither the host, the
network the host is on nor anywhere beyond. IPv6 neighbour discovery passes only to a
link-local or solicited-node address with a hop limit of 255, which finds an address on
the namespace's own link, opens no connection and never leaves that link. Where it is
handed no network, or an entry that is not a subnet holding its gateway, it exits.

The engine's resolver forwards a name it does not hold beyond the host, so a fence holding
its service inside the stack answers the namespace's DNS questions itself. Every question
asked of the resolver on port 53 is sent to the fence instead, which passes on only a
question for the IPv4 or IPv6 address of one of the stack's names it is handed and answers
every other refused without passing it on. It passes on a query of its own rather than the
one asked: the name written lowercase from the entry it matched, under an id it draws from
the system's secure random source, carrying no flag but whether recursion was asked for,
and gives the answer back under the id and question asked, so no bit the service chose
reaches the resolver, which may forward even a stack name beyond the host while that
service is stopped. The question is sent on before the filter sees it, and the filter refuses
every packet to the resolver that does not carry the fence's mark, on the packet and on its
connection, before it passes anything on an open connection, so only the fence's own
sockets reach the resolver. A process can set that mark only while it holds `NET_ADMIN` or
`NET_RAW`, so the fence relies on no container sharing the namespace but itself holding
either: lemonfiber gives `NET_ADMIN` to the fence alone and `NET_RAW` to none of them, and
refuses a stack-only service whose shape would grant either or that another service could
run inside.

## How the stack runs it

| | |
| --- | --- |
| Settings | `LEMONFIBER_FENCE_HOST_ADDRESSES`: the host's own addresses, separated by commas or spaces, refused beside every private range. Required: the fence refuses to start without at least one |
| Settings, inside the stack | `LEMONFIBER_FENCE_NETWORKS`, read by `fence stack`: each of the namespace's own networks as the engine gave it, its subnet and gateway joined by `=`, such as `172.20.0.0/16=172.20.0.1`, separated by commas or spaces. Required: the fence refuses to start without at least one, or with a gateway outside its subnet |
| Names, inside the stack | `LEMONFIBER_FENCE_NAMES`, read by `fence stack`: the names of the stack's services a question may ask for, separated by commas or spaces. Required: the fence refuses to start without it |
| Privilege | `NET_ADMIN` alone, which lemonfiber grants the fence and never the service behind it |
| Whether the engine's containers can hold the rules | `fence nftables`, run once by lemonfiber before it starts a fenced service, in a container of its own with no network, every capability dropped but `NET_ADMIN` and a read-only root filesystem, puts the fence's ruleset in place under a table of its own, `lemonfiber_fence_probe`, reads it back and takes it away again. It prints `held` and exits zero where all of that succeeded, and prints why not and exits non-zero where it did not, so lemonfiber refuses to start the service naming why |
| The host's addresses | `fence addresses`, run once by lemonfiber on the engine's host network with every capability dropped and a read-only root filesystem, prints each address the host holds as its own, one to a line. It reads them twice: every IPv4 address any routing table in `/proc/net/fib_trie` marks local and every IPv6 address `/proc/net/if_inet6` lists, and every address `ip -o addr` lists. It answers only where the two agree. It exits non-zero where they differ, where either holds a line it does not read, where a table marks local a whole range the fence would not refuse anyway, or where it finds no address. The one range it passes over is a local route covering every address in a numbered table: that is policy routing handing marked traffic to a transparent proxy, not an address the host holds |
| The host's render group | `fence render-group`, run once by lemonfiber with the engine's host's `/dev/dri` mounted read-only, every capability dropped and a read-only root filesystem, prints the id of the group owning the render devices under `/dev/dri`, or nothing where there is no `/dev/dri` or no render device in it. It exits non-zero where `/dev/dri` cannot be read or its render devices are owned by more than one group |
| A service that publishes no port | `fence ask <method> <port> <path>`, run once by lemonfiber in a throwaway container joined to the network namespace of a service that publishes no port on the host, with every capability dropped and a read-only root filesystem, asks `127.0.0.1` at that port on that path, follows no redirect, reads at most 64 KiB of the answer and prints its status, its `content-type` and its body, one after the other. It exits non-zero, naming why, where the request is not one it can send or nothing answers |
| Health check | `fence health`, which asks the kernel whether the table, its chain and every set and rule of one ruleset or the other are still in force whole |
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
