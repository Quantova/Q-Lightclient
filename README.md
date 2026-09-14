# Q-Lightclient

The embedded light client for Quantova. It follows the chain by verifying block headers and checking proofs against them, so a wallet or the SDK can trust chain data without running a full node and without ever reaching for classical cryptography.

Quantova is a sovereign post quantum Layer 1, built from scratch, sharing no code, no wire, and no trust assumption with any other chain. The light client inherits that posture end to end. It follows only Quantova headers, checks only Quantova proofs, and holds only Quantova identifiers. Nothing classical secures any part of it. Foreign chains are read only by the oracle, in its own repository, never here.

## What it is for

A light client is the smallest amount of code that can decide, on its own, whether a piece of chain data is real. It does not replay every transaction. It follows the chain of block headers, checks that each header carries a valid consensus attestation, and then verifies short proofs that a given account, transaction, or state value belongs under a header it already trusts.

In the Quantova stack this client is the verification core embedded by the wallet, by the QCore SDK, and by the validator application. It lets each of them read the chain and act on the result without trusting a gateway to tell the truth.

Status. This repository defines the verification interfaces and the corridor and
finality registry. The concrete post quantum verifiers are not implemented here yet, and
the crate is not wired into the wallet, the SDK, or the validator application. The live
verification the chain relies on today is in the Quantova-Chain crates qlc-ethereum,
qlc-cosmos and qtv-btc-spv, not in this repository. Do not treat this crate as a source
of verification until the traits below carry audited implementations.

The interfaces it defines, all intended for post quantum primitives only.

- Header attestations. The interface for refusing a header whose attestation is any scheme other than the module lattice scheme consensus signs with.
- Inclusion and state proofs. The interface for checking membership under a header with SHA-3 Merkle proofs, the same hashing the chain commits with.
- Certificate proofs. The interface for the verifier side of the hash based STARK batch and tally certificates the prover emits.
- Identifiers. Addresses and object identifiers are the Quantova Q1 and family formats, so a value in any foreign encoding does not parse.

## Cryptography

Only NIST standardized post quantum schemes exist here. ML-DSA-65 from FIPS 204 and SLH-DSA from FIPS 205 for signatures, ML-KEM from FIPS 203 for key establishment, and SHA-3 and SHAKE from FIPS 202 for hashing. There is no elliptic curve anywhere and no classical escape hatch. The cryptography is a from scratch reference implementation validated against the NIST vectors. It has not been through an independent security audit, and the chain is at testnet.

## Governance and license

Governed by the crypto policy, POLICY-crypto, in the Quantova-Specs repository, which outranks every other rule here. Commits are authored by the owner only. Dual licensed under Apache 2.0 and MIT.
