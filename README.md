<div align="center">
<a href="https://www.webb.tools/">
    
![Webb Logo](./assets/webb_banner_light.png#gh-light-mode-only)
![Webb Logo](./assets/webb_banner_dark.png#gh-dark-mode-only)
  </a>
  </div>
<p align="left">
    <strong>🚀 CGGMP Threshold ECDSA Distributed Key Generation Protocol 🔑 </strong>
</p>

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/webb-tools/cggmp-threshold-ecdsa/check?style=flat-square)](https://github.com/webb-tools/dkg-substrate/actions) [![Codecov](https://img.shields.io/codecov/c/gh/webb-tools/dkg-substrate?style=flat-square&token=HNT1CEZ01E)](https://codecov.io/gh/webb-tools/dkg-substrate) [![License Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0) [![Twitter](https://img.shields.io/twitter/follow/webbprotocol.svg?style=flat-square&label=Twitter&color=1DA1F2)](https://twitter.com/webbprotocol) [![Telegram](https://img.shields.io/badge/Telegram-gray?logo=telegram)](https://t.me/webbprotocol) [![Discord](https://img.shields.io/discord/833784453251596298.svg?style=flat-square&label=Discord&logo=discord)](https://discord.gg/cv8EfJu3Tn)

<!-- TABLE OF CONTENTS -->
<h2 id="table-of-contents"> 📖 Table of Contents</h2>

<details open="open">
  <summary>Table of Contents</summary>
  <ul>
    <li><a href="#start"> Getting Started</a></li>
    <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#install">Installation</a></li>
        <ul>
          <li><a href="#trouble">Troubleshooting Apple Silicon</a>
          </li>
        </ul>
    </ul>
    <li><a href="#usage">Usage</a></li>
    <ul>
        <li><a href="#quick-start">Quick Start</a></li>
        <ul>
            <li><a href="#standalone">Integration into Substrate</a></li>
            <li><a href="#launch">External Networking</a></li>
        </ul>
    </ul>
    <li><a href="#test">Testing</a></li>
    <li><a href="#contribute">Contributing</a></li>
    <li><a href="#license">License</a></li>
  </ul>  
</details>

<h1 id="start"> Getting Started  🎉 </h1>

This is an implementation of the threshold ECDSA signature multi-party-computation from [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060) with slight modifications. We implement this MPC using the key generation protocol originally from [GG20](https://eprint.iacr.org/2020/540) and implemented by [Zengo](https://github.com/ZenGo-X) in [multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa).

For the key refresh protocol we opt for a fork of Zengo's [fs-dkr](https://github.com/webb-tools/fs-dkr) maintained by us. Together, these complete the key generation and key refreshing protocol. From here, we implement the pre-signing and signing protocols outlined in the aforementioned CGGMP paper. This implementation leverages the infrastructure built by Zengo, namely [round-based-protocol](https://github.com/ZenGo-X/round-based-protocol). We detail how this can be used in a blockchain's gossip network environment such as Substrate, as that motivates this work.

## Prerequisites

This guide uses <https://rustup.rs> installer and the `rustup` tool to manage the Rust toolchain.

First install and configure `rustup`:

```bash
# Install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Configure
source ~/.cargo/env
```

Configure the Rust toolchain to default to the latest stable and nightly versions:

```bash
rustup update
rustup update nightly
```

Great! Now your Rust environment is ready! 🚀🚀

## Installation 💻

Once the development environment is set up, build the repo. This command will build the MPC protocol:
```bash
cargo build --release
```

> NOTE: You _do not need_ to use the release builds! Debug builds can work here as well.

<h1 id="usage"> Usage </h1>

<h2 style="border-bottom:none"> Quick Start ⚡ </h2>

TBD

<h3 id="standalone"> Integration into Substrate </h3>

A main motivation for Webb is integrating this protocol into a blockchain environment such as Substrate. Our intention is to leverage both a blockchain's proof of stake / proof of authority selection mechanism as well as the underlying system's gossip network to bootstrap and execute this multi-party computation offchain. Throughout the lifecycle of the protocol, the participating MPC authorities will post data on-chain to keep the system in sync, such as to select the participating authorities, to govern the thresholds `t` and `n` and more.

An example of how this is possible using the same primitives provided in this repo can be found in our [dkg-substrate](https://github.com/webb-tools/dkg-substrate) repo. Currently the GG20 protocol is being executed. There are wrappers in place for executing any protocol using the [round-based-protocol](https://github.com/ZenGo-X/round-based-protocol) architecture. Slight modifications might be necessary and we aim to have this repo integrated into Substrate once it is working and tested here.

<h3 id="standalone"> External Networking </h3>

Not included in this library is a server-oriented execution protocol. There are examples of how this can be done using GG20 in [multi-party-ecdas](https://github.com/ZenGo-X/multi-party-ecdsa/tree/master/examples). We welcome contributions to add a similar example here, but at the moment it will not be prioritized.

There are a variety of other external networking options one can choose between such as point-to-point channels, gossip networks, and or gRPC server coordinators. Each has different trade-offs. Point-to-point channels and gRPC server coordination allow one to run this protocol in the most simple manner, since the network topology is effectively decided on startup. In a gossip network environment this isn't always the case, therefore gossiping and re-gossiping messages using a method such as [gossipsub](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md) from [libp2p](https://libp2p.io/) is recommended.

<h2 id="test"> Testing 🧪 </h2>

The following instructions outlines how to run dkg-substrate's base test suite and E2E test suite.

### To run base tests

```
cargo test
```

<h2 id="contribute"> Contributing </h2>

Interested in contributing to the Webb's MPC research? Thank you so much for your interest! We are always appreciative for contributions from the open-source community!

If you have a contribution in mind, please check out our [Contribution Guide](./.github/CONTRIBUTING.md) for information on how to do so. We are excited for your first contribution!

<h2 id="license"> License </h2>

Licensed under <a href="LICENSE">GNU General Public License v3.0</a>.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the GNU General Public License v3.0 license, shall be licensed as above, without any additional terms or conditions.
