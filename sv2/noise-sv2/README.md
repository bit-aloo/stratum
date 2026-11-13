
# noise_sv2

[![crates.io](https://img.shields.io/crates/v/noise_sv2.svg)](https://crates.io/crates/noise_sv2)
[![docs.rs](https://docs.rs/noise_sv2/badge.svg)](https://docs.rs/noise_sv2)
[![rustc+](https://img.shields.io/badge/rustc-1.75.0%2B-lightgrey.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/stratum-mining/stratum/blob/main/LICENSE.md)
[![codecov](https://codecov.io/gh/stratum-mining/stratum/branch/main/graph/badge.svg?flag=noise_sv2-coverage)](https://codecov.io/gh/stratum-mining/stratum)

`noise_sv2` is primarily intended to secure communication in the Stratum V2 (Sv2) protocol. It handles the necessary Noise handshakes, encrypts outgoing messages, and decrypts incoming responses, ensuring privacy and integrity across the communication link between Sv2 roles. See the [Protocol Security specification](https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md) for more details.

## Key Capabilities
* **Secure Communication**: `InitiatorAuthentication` explicitly selects authority authentication or an encrypted, unauthenticated connection. `ResponderIdentity` selects unsigned operation, signing with an authority private key, or presenting a pre-issued certificate and static key.
* **Cipher Support**: Uses `ChaCha20-Poly1305` for authenticated encryption.
* **Handshake Roles**: Implements the `Initiator` and `Responder` roles required by the Noise handshake, allowing both sides of a connection to establish secure communication.
* **Cryptographic Helpers**: Facilitates the management of cryptographic state and encryption operations.

## Usage
To include this crate in your project, run:

```bash
cargo add noise_sv2
```

This crate can be built with the following feature flags:

- `std`: Enable usage of rust `std` library, enabled by default.

In order to use this crate in a `#![no_std]` environment, use the `--no-default-features` to remove the `std` feature.

### Authentication and credentials

Initiators select a policy when they are constructed:

```rust
use noise_sv2::{Initiator, InitiatorAuthentication};

// Pin the authority public key for connections across a network boundary.
let authentication = InitiatorAuthentication::from_raw_k(authority_public_key_bytes)?;
let initiator = Initiator::new(authentication);

// Only on a trusted network: encrypted transport without responder authentication.
let initiator = Initiator::new(InitiatorAuthentication::Unauthenticated);
```

Responders borrow a reusable identity, and generate fresh ephemeral keys for each connection:

```rust
use noise_sv2::{CertifiedStaticKey, Responder, ResponderIdentity};

// Production: validate the certificate's binding to the static key once when loading credentials.
let credentials = CertifiedStaticKey::new(static_key, certificate, &authority_public_key)?;
let identity = ResponderIdentity::Certified(credentials);
let responder = Responder::new(&identity);

// Development and testing: keep the authority private key on the server and sign per handshake.
let identity = ResponderIdentity::Authority {
    authority: authority_keypair,
    certificate_validity: 3600, // seconds
};
let responder = Responder::new(&identity);

// No authority credentials. Initiators that require authority authentication reject this mode.
let responder = Responder::new(&ResponderIdentity::Unauthenticated);
```

An offline issuer calls `Certificate::issue` (or `issue_with_rng`) over the server's static public
key and its chosen validity window. `Certificate::to_bytes` exports the 74-byte wire encoding;
`Certificate::from` decodes it. Decoding alone does not authenticate the certificate.
`Certificate::verify_with_now` always requires an authority public key and borrows the certificate.

`CertifiedStaticKey::new` checks the certificate format, signature and static-key binding. It
permits future and expired certificates; the initiator checks time validity at each handshake,
with ten seconds of clock leeway at either edge. Servers must arrange certificate renewal and can
inspect the deadline through `CertifiedStaticKey::certificate().not_valid_after()`. Existing
transport sessions are unaffected by certificate expiration or rotation.

The authority private key should stay on the issuing machine. Neither this crate nor the protocol
defines revocation, so a compromised authority key can impersonate the operator for as long as
clients pin its public key. An unauthenticated transport does not record its authentication policy
in the returned `NoiseEngine`; applications must retain that choice if they need it later.

For `no_std`, use `Initiator::new_with_rng`, `Responder::new_with_rng`, and the handshake methods
with explicit timestamps and randomness. Raw-key parsing belongs to `InitiatorAuthentication` and
`ResponderIdentity`, and is available without `std`.

### Migration from 2.x

- Replace `Initiator::new(Some(key))` with `Initiator::new(InitiatorAuthentication::Authority(key))`.
- Replace `Initiator::new(None)` and `Initiator::without_pk()` with
  `Initiator::new(InitiatorAuthentication::Unauthenticated)`.
- Move `Initiator::from_raw_k` to `InitiatorAuthentication::from_raw_k`, then construct the initiator.
- Replace `Responder::new(authority, validity)` with a borrowed `ResponderIdentity::Authority`.
- Move `Responder::from_authority_kp` to `ResponderIdentity::from_authority_kp`, then construct the
  responder. Durations exceeding `u32::MAX` seconds now return an error instead of truncating.
- Replace `Responder::from_certificate` with `ResponderIdentity::Certified` after validating the
  certificate/key pair through `CertifiedStaticKey::new`. This needs only the authority public key.
- Replace `SignatureNoiseMessage` and raw-buffer signing with `Certificate` and its issuance methods.

### Examples

This crate provides example on establishing a secure line:

1. **[Certified Handshake Example](examples/certified_handshake.rs)**:
   Issue a certificate separately, load a checked static-key/certificate pair, and authenticate
   without supplying the authority private key to the responder.

2. **[Noise Handshake Example](https://github.com/stratum-mining/stratum/blob/main/sv2/noise-sv2/examples/handshake.rs)**:
   Establish a secure line of communication between an Initiator and Responder via the Noise
   protocol, allowing for the encryption and decryption of a secret message.

### Benches

This crate includes Criterion benchmarks under `benches/` covering:

* Noise handshake performance (`handshake.rs`)
* Encrypted message roundtrips after handshake (`roundtrip.rs`)

Benchmarks are intended for regression tracking and relative comparison, not absolute performance claims.

Example benchmark output and methodology are documented in [BENCHES.md](./BENCHES.md).

Run them with:

```bash
cargo bench
```
