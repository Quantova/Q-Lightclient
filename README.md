# Q-Lightclient

The light client library for the Quantova stack. It holds two kinds of verifier that never mix. The first follows Quantova itself, so a wallet or the SDK can trust chain data without running a full node. The second follows foreign chains for the bridge, so a deposit on Bitcoin or Ethereum or Cosmos can be checked against that chain's own consensus rather than taken on trust from a relayer.

Quantova is a sovereign post quantum Layer 1, built from scratch, sharing no code, no wire, and no trust assumption with any other chain. Nothing classical secures Quantova. The Quantova verifier in this repository inherits that posture end to end, it follows only Quantova headers, checks only Quantova proofs with the module lattice scheme and SHA-3, and holds only Quantova identifiers.

The foreign verifiers are a different job under a different rule. A Bitcoin header chain is checked with SHA-256d proof of work, each foreign chain against its own consensus, because a chain can only be read with its own cryptography. That foreign cryptography is confined to the foreign verifiers, it is used only to read a foreign chain, and it never crosses the Airlock into Quantova. Only a post quantum attestation and a hash based STARK reach the chain, so no elliptic curve ever secures Quantova.

## What it is for

A light client is the smallest amount of code that can decide, on its own, whether a piece of chain data is real. It does not replay every transaction. It follows a chain of block headers, checks that each header carries a valid consensus proof, and then verifies short proofs that a given account, transaction, or state value belongs under a header it already trusts.

The Quantova verifier is the core embedded by the wallet, by the QCore SDK, and by the validator application. It lets each of them read Quantova and act on the result without trusting a gateway to tell the truth. The foreign verifiers are the read side of the bridge, they let the oracle establish that a foreign deposit really happened under that foreign chain's own consensus before Quantova ever mints against it.

What the Quantova verifier checks, all with post quantum primitives only.

- Header attestations. Consensus signs with the module lattice scheme and nothing else, so a header whose attestation is any other scheme is refused. This matches the consensus rule frozen in the conformance vectors.
- Inclusion and state proofs. Membership under a header is checked with SHA-3 Merkle proofs, the same hashing the chain commits with.
- Certificate proofs. Batch and tally certificates arrive as hash based STARK proofs from the prover, which rest on hashing alone with no pairing and no elliptic curve operation.
- Identifiers. Addresses and object identifiers are the Quantova Q1 and family formats, so a value in any foreign encoding does not parse.

What the foreign verifiers check, each with the target chain's own rules.

- Bitcoin. A proof of work header chain and a Merkle inclusion of the deposit, all SHA-256d, no foreign public key crypto at all.
- Ethereum and the EVM chains. The verifier side of the foreign chain's own consensus proof.
- Cosmos chains. The verifier side of the foreign chain's own commit.

## Isolation

The classical cryptography the foreign verifiers use is the target chain's own, and it is fenced off. It reads a foreign chain and produces a post quantum attestation and a hash STARK, and only those two artifacts cross the Airlock into Quantova. The crate deny gate keeps classical cryptography crates out of the tree, and the foreign verifiers are deliberate, reviewed, minimal implementations that exist solely to read a foreign chain, never to secure Quantova. The clean structural home for the foreign verifiers is the oracle side alongside the rest of the bridge, and moving them there is tracked work.

## Status

This repository is at testnet. The Quantova verifier follows the header and proof formats frozen in Quantova-Specs and Quantova-Chain and pins them by git tag. The foreign verifiers carry real logic checked against real foreign chain vectors.

## Cryptography

The Quantova side uses only NIST standardized post quantum schemes, ML-DSA-65 from FIPS 204 and SLH-DSA from FIPS 205 for signatures, ML-KEM from FIPS 203 for key establishment, and SHA-3 and SHAKE from FIPS 202 for hashing. The foreign side carries the minimum classical verification each foreign chain needs to be read, isolated as above. The cryptography is a from scratch reference implementation validated against the published vectors. It has not been through an independent security audit, and the chain is at testnet.

## Governance and license

Governed by the crypto policy, POLICY-crypto, in the Quantova-Specs repository, which outranks every other rule here. Commits are authored by the owner only. Dual licensed under Apache 2.0 and MIT.
