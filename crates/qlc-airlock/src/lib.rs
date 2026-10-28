#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;

use qlc_core::VerificationTier;
use qlc_registry::{corridor_for_id, NetworkId, RegistryError, TierLedger};
use qlc_stark::corridors::{is_proof_corridor, nonce_from_source_ref, ProofStatement};
use qlc_stark::{shake256_256, StarkStatement, StatementKind};

pub const MAGIC: [u8; 4] = *b"QALK";
pub const VERSION: u8 = 2;

pub const SUITE_ML_DSA: u8 = 0x01;
pub const SUITE_HASH_STARK: u8 = 0x02;

pub const ML_DSA_65_SIG_LEN: usize = 3309;
pub const STARK_STATEMENT_LEN: usize = StarkStatement::ENCODED_LEN;
pub const CLAIM_LEN: usize = ProofStatement::ENCODED_LEN;
pub const MIN_HASH_STARK_LEN: usize = STARK_STATEMENT_LEN + CLAIM_LEN + 1;
pub const MAX_HASH_STARK_LEN: usize = 32 << 20;

const REPLAY_DOMAIN: &[u8] = b"quantova/airlock/replay/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressError {
    TooShort,
    BadMagic,
    BadVersion,
    UnknownSuite {
        slot: usize,
        suite: u8,
    },
    SlotOutOfOrder {
        slot: usize,
        expected: u8,
        found: u8,
    },
    BadArtifactLength {
        slot: usize,
    },
    Truncated {
        slot: usize,
    },
    TrailingBytes,
    BadStatement,
    NotProofCorridor,
    WrongDestination {
        expected: u32,
        found: u32,
    },
    UnknownCorridor {
        corridor_id: u32,
    },
    CorridorKindMismatch {
        corridor_id: u32,
    },
    UnboundClaim,
    ShallowFinality {
        required: u32,
        found: u32,
    },
    Replay,
    BadAttestation,
    BadProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsaAttestation {
    signature: Vec<u8>,
}

impl MlDsaAttestation {
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingress {
    attestation: MlDsaAttestation,
    statement: StarkStatement,
    claim: ProofStatement,
    proof: Vec<u8>,
    tier: VerificationTier,
}

pub fn replay_key_of(claim: &ProofStatement) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(REPLAY_DOMAIN.len() + 4 + 32);
    bytes.extend_from_slice(REPLAY_DOMAIN);
    bytes.extend_from_slice(&claim.corridor_id.to_le_bytes());
    bytes.extend_from_slice(&claim.event.source_ref);
    shake256_256(&bytes)
}

impl Ingress {
    pub fn attestation(&self) -> &MlDsaAttestation {
        &self.attestation
    }

    pub fn statement(&self) -> &StarkStatement {
        &self.statement
    }

    pub fn claim(&self) -> &ProofStatement {
        &self.claim
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Airlock {
    dest_chain_id: u32,
    seen: BTreeSet<[u8; 32]>,
    tiers: TierLedger,
}

impl Airlock {
    pub fn new(dest_chain_id: u32) -> Airlock {
        Airlock {
            dest_chain_id,
            seen: BTreeSet::new(),
            tiers: TierLedger::new(),
        }
    }

    pub fn restore(
        dest_chain_id: u32,
        seen: impl IntoIterator<Item = [u8; 32]>,
        tiers: TierLedger,
    ) -> Airlock {
        Airlock {
            dest_chain_id,
            seen: seen.into_iter().collect(),
            tiers,
        }
    }

    pub fn seen(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.seen.iter()
    }

    pub fn tiers(&self) -> &TierLedger {
        &self.tiers
    }

    pub fn upgrade_tier(
        &mut self,
        id: NetworkId,
        proposed: VerificationTier,
    ) -> Result<VerificationTier, RegistryError> {
        self.tiers.upgrade(id, proposed)
    }
}

fn check_statement(
    statement: &StarkStatement,
    dest_chain_id: u32,
) -> Result<VerificationTier, IngressError> {
    if statement.dest_chain_id != dest_chain_id {
        return Err(IngressError::WrongDestination {
            expected: dest_chain_id,
            found: statement.dest_chain_id,
        });
    }
    if !is_proof_corridor(statement.kind) {
        return Err(IngressError::NotProofCorridor);
    }
    let corridor =
        corridor_for_id(statement.corridor_id).map_err(|_| IngressError::UnknownCorridor {
            corridor_id: statement.corridor_id,
        })?;
    let expected_tier = match statement.kind {
        StatementKind::BitcoinSpv => VerificationTier::Spv,
        StatementKind::EvmLightClient => VerificationTier::LightClient,
        StatementKind::CosmosTendermint => VerificationTier::LightClient,
        _ => return Err(IngressError::NotProofCorridor),
    };
    if corridor.tier != expected_tier || !kind_allows_corridor(statement.kind, corridor.id) {
        return Err(IngressError::CorridorKindMismatch {
            corridor_id: statement.corridor_id,
        });
    }
    Ok(expected_tier)
}

fn check_claim(statement: &StarkStatement, claim: &ProofStatement) -> Result<(), IngressError> {
    let corridor =
        corridor_for_id(statement.corridor_id).map_err(|_| IngressError::UnknownCorridor {
            corridor_id: statement.corridor_id,
        })?;
    if claim.corridor_id != statement.corridor_id
        || claim.dest_chain_id != statement.dest_chain_id
        || claim.nonce != statement.nonce
        || claim.kind != statement.kind
        || claim.nonce != nonce_from_source_ref(&claim.event.source_ref)
        || shake256_256(&claim.encode()) != statement.public_input_digest
    {
        return Err(IngressError::UnboundClaim);
    }
    if claim.finality_depth < corridor.finality.confirmation_depth {
        return Err(IngressError::ShallowFinality {
            required: corridor.finality.confirmation_depth,
            found: claim.finality_depth,
        });
    }
    Ok(())
}

fn read_slot(bytes: &[u8], off: usize, slot: usize) -> Result<(u8, &[u8], usize), IngressError> {
    if off + 5 > bytes.len() {
        return Err(IngressError::Truncated { slot });
    }
    let suite = bytes[off];
    if suite != SUITE_ML_DSA && suite != SUITE_HASH_STARK {
        return Err(IngressError::UnknownSuite { slot, suite });
    }
    let len = u32::from_le_bytes([
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
    ]) as usize;
    if len > MAX_HASH_STARK_LEN {
        return Err(IngressError::BadArtifactLength { slot });
    }
    let start = off + 5;
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(IngressError::Truncated { slot }),
    };
    if end > bytes.len() {
        return Err(IngressError::Truncated { slot });
    }
    Ok((suite, &bytes[start..end], end))
}

pub fn parse_ingress(bytes: &[u8], dest_chain_id: u32) -> Result<Ingress, IngressError> {
    if bytes.len() < MAGIC.len() + 1 {
        return Err(IngressError::TooShort);
    }
    if bytes[0..4] != MAGIC {
        return Err(IngressError::BadMagic);
    }
    if bytes[4] != VERSION {
        return Err(IngressError::BadVersion);
    }

    let (suite0, payload0, off1) = read_slot(bytes, 5, 0)?;
    if suite0 != SUITE_ML_DSA {
        return Err(IngressError::SlotOutOfOrder {
            slot: 0,
            expected: SUITE_ML_DSA,
            found: suite0,
        });
    }
    if payload0.len() != ML_DSA_65_SIG_LEN {
        return Err(IngressError::BadArtifactLength { slot: 0 });
    }

    let (suite1, payload1, off2) = read_slot(bytes, off1, 1)?;
    if suite1 != SUITE_HASH_STARK {
        return Err(IngressError::SlotOutOfOrder {
            slot: 1,
            expected: SUITE_HASH_STARK,
            found: suite1,
        });
    }
    if payload1.len() < MIN_HASH_STARK_LEN {
        return Err(IngressError::BadArtifactLength { slot: 1 });
    }

    if off2 != bytes.len() {
        return Err(IngressError::TrailingBytes);
    }

    let statement = StarkStatement::decode(&payload1[0..STARK_STATEMENT_LEN])
        .ok_or(IngressError::BadStatement)?;
    let tier = check_statement(&statement, dest_chain_id)?;
    let claim =
        ProofStatement::decode(&payload1[STARK_STATEMENT_LEN..STARK_STATEMENT_LEN + CLAIM_LEN])
            .ok_or(IngressError::BadStatement)?;
    check_claim(&statement, &claim)?;

    Ok(Ingress {
        attestation: MlDsaAttestation {
            signature: payload0.to_vec(),
        },
        statement,
        claim,
        proof: payload1[STARK_STATEMENT_LEN + CLAIM_LEN..].to_vec(),
        tier,
    })
}

fn kind_allows_corridor(kind: StatementKind, id: NetworkId) -> bool {
    use NetworkId::*;
    match kind {
        StatementKind::BitcoinSpv => matches!(id, Bitcoin),
        StatementKind::EvmLightClient => matches!(id, Ethereum),
        StatementKind::CosmosTendermint => matches!(id, CosmosHub),
        _ => false,
    }
}

fn push_slot(out: &mut Vec<u8>, suite: u8, payload: &[u8]) {
    out.push(suite);
    out.extend_from_slice(&(payload.len().min(u32::MAX as usize) as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

pub fn encode_ingress(
    attestation: &[u8],
    claim: &ProofStatement,
    proof: &[u8],
) -> Result<Vec<u8>, IngressError> {
    if attestation.len() != ML_DSA_65_SIG_LEN {
        return Err(IngressError::BadArtifactLength { slot: 0 });
    }
    let mut stark_payload = claim.to_stark_statement().encode();
    stark_payload.extend_from_slice(&claim.encode());
    stark_payload.extend_from_slice(proof);
    if stark_payload.len() < MIN_HASH_STARK_LEN || stark_payload.len() > MAX_HASH_STARK_LEN {
        return Err(IngressError::BadArtifactLength { slot: 1 });
    }
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    push_slot(&mut out, SUITE_ML_DSA, attestation);
    push_slot(&mut out, SUITE_HASH_STARK, &stark_payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlc_stark::corridors::EventClaim;
    use qlc_stark::{StatementKind, QUANTOVA_DEST_CHAIN_ID};

    pub(super) fn claim(
        corridor_id: u32,
        dest_chain_id: u32,
        kind: StatementKind,
    ) -> ProofStatement {
        let source_ref = [0x11u8; 32];
        ProofStatement {
            corridor_id,
            dest_chain_id,
            nonce: nonce_from_source_ref(&source_ref),
            kind,
            anchor: [0x44u8; 32],
            event: EventClaim {
                source_ref,
                asset_id: [0x22u8; 16],
                amount: 1_000,
                recipient: [0x33u8; 32],
            },
            finality_depth: 1_000_000,
        }
    }

    fn stark_payload() -> Vec<u8> {
        let mut out = proof_statement().to_stark_statement().encode();
        out.extend_from_slice(&proof_statement().encode());
        out
    }

    const FOREIGN_SUITE_ED25519: u8 = 0x10;
    const FOREIGN_SUITE_SECP256K1: u8 = 0x11;
    const FOREIGN_SUITE_BLS: u8 = 0x12;

    pub(super) fn ml_dsa_attestation() -> Vec<u8> {
        vec![0x07u8; ML_DSA_65_SIG_LEN]
    }

    fn proof_statement() -> ProofStatement {
        claim(43, 4801, StatementKind::BitcoinSpv)
    }

    fn ed25519_signature() -> Vec<u8> {
        vec![0xa1u8; 64]
    }

    fn ed25519_public_key() -> Vec<u8> {
        vec![0xa2u8; 32]
    }

    fn secp256k1_compressed_pubkey() -> Vec<u8> {
        let mut v = vec![0x02u8];
        v.extend_from_slice(&[0xb1u8; 32]);
        v
    }

    fn secp256k1_ecdsa_der() -> Vec<u8> {
        let mut v = vec![0x30u8, 0x44, 0x02, 0x20];
        v.extend_from_slice(&[0xc1u8; 32]);
        v.extend_from_slice(&[0x02u8, 0x20]);
        v.extend_from_slice(&[0xc2u8; 32]);
        v
    }

    fn bls12_381_g1_compressed() -> Vec<u8> {
        let mut v = vec![0xa0u8];
        v.extend_from_slice(&[0xd1u8; 47]);
        v
    }

    fn bls12_381_g2_compressed() -> Vec<u8> {
        let mut v = vec![0xa0u8];
        v.extend_from_slice(&[0xd2u8; 95]);
        v
    }

    fn wrap_two_slots(suite0: u8, payload0: &[u8], suite1: u8, payload1: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        push_slot(&mut out, suite0, payload0);
        push_slot(&mut out, suite1, payload1);
        out
    }

    #[test]
    fn the_statement_length_constant_tracks_the_stark_encoding() {
        assert_eq!(
            proof_statement().to_stark_statement().encode().len(),
            STARK_STATEMENT_LEN
        );
    }

    #[test]
    fn a_well_formed_ingress_parses_to_the_two_post_quantum_artifacts() {
        let bytes =
            encode_ingress(&ml_dsa_attestation(), &proof_statement(), &[0x01u8; 200]).unwrap();
        let ingress = parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID).unwrap();
        assert_eq!(ingress.attestation().signature().len(), ML_DSA_65_SIG_LEN);
        assert!(is_proof_corridor(ingress.statement().kind));
        assert_eq!(ingress.proof(), &[0x01u8; 200][..]);
    }

    #[test]
    fn an_empty_proof_slot_is_refused_by_the_encoder() {
        assert_eq!(
            encode_ingress(&ml_dsa_attestation(), &proof_statement(), &[]),
            Err(IngressError::BadArtifactLength { slot: 1 })
        );
        assert!(encode_ingress(&ml_dsa_attestation(), &proof_statement(), &[0x01u8]).is_ok());
    }

    #[test]
    fn an_oversized_proof_slot_is_refused() {
        let huge = vec![0u8; MAX_HASH_STARK_LEN + 1];
        assert_eq!(
            encode_ingress(&ml_dsa_attestation(), &proof_statement(), &huge),
            Err(IngressError::BadArtifactLength { slot: 1 })
        );
        let bytes = wrap_two_slots(SUITE_ML_DSA, &ml_dsa_attestation(), SUITE_HASH_STARK, &huge);
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadArtifactLength { slot: 1 })
        );
    }

    #[test]
    fn every_proof_corridor_statement_crosses_the_airlock() {
        for (kind, corridor_id) in [
            (StatementKind::BitcoinSpv, 43u32),
            (StatementKind::EvmLightClient, 2u32),
            (StatementKind::CosmosTendermint, 16u32),
        ] {
            let statement = claim(corridor_id, 4801, kind);
            let bytes = encode_ingress(&ml_dsa_attestation(), &statement, &[0x02u8; 8]).unwrap();
            assert_eq!(
                parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID)
                    .unwrap()
                    .statement()
                    .kind,
                kind
            );
        }
    }

    #[test]
    fn a_proof_under_a_mismatched_or_unknown_corridor_is_rejected() {
        let mismatched = claim(38, 4801, StatementKind::BitcoinSpv);
        let bytes = encode_ingress(&ml_dsa_attestation(), &mismatched, &[0x02u8; 8]).unwrap();
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::CorridorKindMismatch { corridor_id: 38 })
        );

        let retired = claim(0, 4801, StatementKind::BitcoinSpv);
        let bytes = encode_ingress(&ml_dsa_attestation(), &retired, &[0x02u8; 8]).unwrap();
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::UnknownCorridor { corridor_id: 0 })
        );

        let unknown = claim(4_000_000_000, 4801, StatementKind::EvmLightClient);
        let bytes = encode_ingress(&ml_dsa_attestation(), &unknown, &[0x02u8; 8]).unwrap();
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::UnknownCorridor {
                corridor_id: 4_000_000_000
            })
        );

        let cross = claim(16, 4801, StatementKind::EvmLightClient);
        let bytes = encode_ingress(&ml_dsa_attestation(), &cross, &[0x02u8; 8]).unwrap();
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::CorridorKindMismatch { corridor_id: 16 })
        );
    }

    #[test]
    fn a_generic_non_proof_statement_does_not_cross() {
        let statement = claim(1, 4801, StatementKind::LightClientStep);
        let bytes = encode_ingress(&ml_dsa_attestation(), &statement, &[0x02u8; 8]).unwrap();
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::NotProofCorridor)
        );
    }

    #[test]
    fn a_statement_addressed_to_another_chain_does_not_cross() {
        let statement = claim(0, 4802, StatementKind::BitcoinSpv);
        let bytes = encode_ingress(&ml_dsa_attestation(), &statement, &[0x02u8; 8]).unwrap();
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::WrongDestination {
                expected: QUANTOVA_DEST_CHAIN_ID,
                found: 4802
            })
        );
    }

    #[test]
    fn exactly_two_artifacts_a_third_slot_is_trailing() {
        let mut bytes =
            encode_ingress(&ml_dsa_attestation(), &proof_statement(), &[0x01u8; 8]).unwrap();
        push_slot(&mut bytes, SUITE_ML_DSA, &ml_dsa_attestation());
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::TrailingBytes)
        );
    }

    #[test]
    fn exactly_two_artifacts_a_single_slot_is_truncated() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        push_slot(&mut bytes, SUITE_ML_DSA, &ml_dsa_attestation());
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::Truncated { slot: 1 })
        );
    }

    #[test]
    fn empty_input_is_too_short() {
        assert_eq!(
            parse_ingress(&[], QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::TooShort)
        );
    }

    #[test]
    fn the_two_slots_may_not_be_swapped() {
        let mut stark_payload = stark_payload();
        stark_payload.extend_from_slice(&[0x01u8; 8]);
        let bytes = wrap_two_slots(
            SUITE_HASH_STARK,
            &stark_payload,
            SUITE_ML_DSA,
            &ml_dsa_attestation(),
        );
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::SlotOutOfOrder {
                slot: 0,
                expected: SUITE_ML_DSA,
                found: SUITE_HASH_STARK
            })
        );
    }

    #[test]
    fn negative_vector_ed25519_signature_is_unparseable() {
        let sig = ed25519_signature();
        assert_eq!(
            parse_ingress(&sig, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadMagic)
        );

        let wrapped = wrap_two_slots(
            FOREIGN_SUITE_ED25519,
            &sig,
            SUITE_HASH_STARK,
            &stark_payload(),
        );
        assert_eq!(
            parse_ingress(&wrapped, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::UnknownSuite {
                slot: 0,
                suite: FOREIGN_SUITE_ED25519
            })
        );

        let spoofed = wrap_two_slots(SUITE_ML_DSA, &sig, SUITE_HASH_STARK, &stark_payload());
        assert_eq!(
            parse_ingress(&spoofed, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadArtifactLength { slot: 0 })
        );
    }

    #[test]
    fn negative_vector_ed25519_public_key_is_unparseable() {
        let key = ed25519_public_key();
        assert_eq!(
            parse_ingress(&key, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadMagic)
        );
        let spoofed = wrap_two_slots(SUITE_ML_DSA, &key, SUITE_HASH_STARK, &stark_payload());
        assert_eq!(
            parse_ingress(&spoofed, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadArtifactLength { slot: 0 })
        );
    }

    #[test]
    fn negative_vector_secp256k1_pubkey_is_unparseable() {
        let key = secp256k1_compressed_pubkey();
        assert_eq!(
            parse_ingress(&key, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadMagic)
        );

        let wrapped = wrap_two_slots(
            FOREIGN_SUITE_SECP256K1,
            &key,
            SUITE_HASH_STARK,
            &stark_payload(),
        );
        assert_eq!(
            parse_ingress(&wrapped, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::UnknownSuite {
                slot: 0,
                suite: FOREIGN_SUITE_SECP256K1
            })
        );

        let spoofed = wrap_two_slots(SUITE_ML_DSA, &key, SUITE_HASH_STARK, &stark_payload());
        assert_eq!(
            parse_ingress(&spoofed, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadArtifactLength { slot: 0 })
        );
    }

    #[test]
    fn negative_vector_secp256k1_ecdsa_der_is_unparseable() {
        let sig = secp256k1_ecdsa_der();
        assert_eq!(
            parse_ingress(&sig, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadMagic)
        );
        let spoofed = wrap_two_slots(SUITE_ML_DSA, &sig, SUITE_HASH_STARK, &stark_payload());
        assert_eq!(
            parse_ingress(&spoofed, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadArtifactLength { slot: 0 })
        );
    }

    #[test]
    fn negative_vector_bls12_381_g1_is_unparseable() {
        let point = bls12_381_g1_compressed();
        assert_eq!(
            parse_ingress(&point, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadMagic)
        );

        let wrapped = wrap_two_slots(
            FOREIGN_SUITE_BLS,
            &point,
            SUITE_HASH_STARK,
            &stark_payload(),
        );
        assert_eq!(
            parse_ingress(&wrapped, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::UnknownSuite {
                slot: 0,
                suite: FOREIGN_SUITE_BLS
            })
        );

        let spoofed = wrap_two_slots(SUITE_ML_DSA, &point, SUITE_HASH_STARK, &stark_payload());
        assert_eq!(
            parse_ingress(&spoofed, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadArtifactLength { slot: 0 })
        );
    }

    #[test]
    fn negative_vector_bls12_381_g2_is_unparseable() {
        let point = bls12_381_g2_compressed();
        assert_eq!(
            parse_ingress(&point, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadMagic)
        );
        let spoofed = wrap_two_slots(SUITE_ML_DSA, &point, SUITE_HASH_STARK, &stark_payload());
        assert_eq!(
            parse_ingress(&spoofed, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::BadArtifactLength { slot: 0 })
        );
    }

    #[test]
    fn a_foreign_suite_in_the_proof_slot_is_also_refused() {
        let bytes = wrap_two_slots(
            SUITE_ML_DSA,
            &ml_dsa_attestation(),
            FOREIGN_SUITE_BLS,
            &bls12_381_g2_compressed(),
        );
        assert_eq!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID),
            Err(IngressError::UnknownSuite {
                slot: 1,
                suite: FOREIGN_SUITE_BLS
            })
        );
    }
}

#[cfg(test)]
mod same_family_boundary_tests {
    use super::tests::{claim, ml_dsa_attestation};
    use super::*;
    use qlc_stark::{StatementKind, QUANTOVA_DEST_CHAIN_ID};

    #[test]
    fn the_airlock_does_not_separate_two_corridors_of_the_same_tier_and_family() {
        let ethereum = claim(2, 4801, StatementKind::EvmLightClient);
        let bytes = encode_ingress(&ml_dsa_attestation(), &ethereum, &[0x02u8; 8]).unwrap();
        assert!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID).is_ok(),
            "an EVM proof under the Ethereum corridor crosses"
        );

        let arbitrum = claim(6, 4801, StatementKind::EvmLightClient);
        let bytes = encode_ingress(&ml_dsa_attestation(), &arbitrum, &[0x02u8; 8]).unwrap();
        assert!(
            parse_ingress(&bytes, QUANTOVA_DEST_CHAIN_ID).is_err(),
            "corridor six no longer carries a light-client verifier, so an EVM light-client \
             statement no longer crosses under it"
        );
    }
}
