// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::spv::DepositProof;
use crate::SpvError;
use qlc_stark::corridors::ProofStatement;
use qlc_stark::shake256_256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinCheckedFacts {
    pub network_magic: [u8; 4],
    pub tip_height: u32,
    pub deposit_height: u32,
    pub deposit_block_hash: [u8; 32],
    pub deposit_merkle_root: [u8; 32],
}

impl BitcoinCheckedFacts {
    pub const ENCODED_LEN: usize = 4 + 4 + 4 + 32 + 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.network_magic);
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        out.extend_from_slice(&self.deposit_height.to_le_bytes());
        out.extend_from_slice(&self.deposit_block_hash);
        out.extend_from_slice(&self.deposit_merkle_root);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProveReadyWitness {
    pub statement: ProofStatement,
    pub public_input_digest: [u8; 32],
    pub facts: BitcoinCheckedFacts,
}

impl ProveReadyWitness {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.statement.encode();
        out.extend_from_slice(&self.facts.encode());
        out
    }
}

fn digest_of(statement: &ProofStatement, facts: &BitcoinCheckedFacts) -> [u8; 32] {
    let mut buf = statement.encode();
    buf.extend_from_slice(&facts.encode());
    shake256_256(&buf)
}

impl<'a> DepositProof<'a> {
    pub fn prove_ready_witness(&self) -> Result<ProveReadyWitness, SpvError> {
        let proven = self.prove()?;
        let facts = BitcoinCheckedFacts {
            network_magic: self.params.magic,
            tip_height: self.chain.tip_height,
            deposit_height: proven.confirmed.deposit_height,
            deposit_block_hash: proven.confirmed.block_hash,
            deposit_merkle_root: proven.confirmed.merkle_root,
        };
        let public_input_digest = digest_of(&proven.statement, &facts);
        Ok(ProveReadyWitness {
            statement: proven.statement,
            public_input_digest,
            facts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_chain;
    use crate::params::BITCOIN;
    use crate::{BlockHeader, MerkleStep};
    use qlc_stark::corridors::{bitcoin_spv, EventClaim};

    fn from_hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn reversed(s: &str) -> [u8; 32] {
        let mut bytes = from_hex(s);
        bytes.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    const B170: &str = "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70";
    const B171: &str = "01000000eea2d48d2fced4346842835c659e493d323f06d4034469a8905714d100000000f293c86973e758ccd11975fa464d4c3e8500979c95425c7be6f0a65314d2f2d5c9ba6a49ffff001d07a8f226";
    const B172: &str = "01000000e0b4bf8d80026bbec5370a7bb06af54257a9679cef387fab8c53ecc900000000d578b0399b91624a8da53552035fecdd8f4ba2b9c69dfbda68d651fcb9f99c388dbc6a49ffff001d35464c5d";
    const B173: &str = "0100000054686892dd112de389acc225accc0118765f9c51c2ec9306f6abefe3000000005209a3e77e3679703f6b7f039fb9e054d7862e6eaad617e8e3f3d81d297e966015be6a49ffff001d21ac0323";
    const B174: &str = "01000000c585ac476b5878f0f1917826430b3daec278ef28c121c2ec9dd6e9dc000000008195110f0743ab43d4146798c962b8d101e325f4afdf8e936d15c2d51371b9cc7dc06a49ffff001d32915d0f";
    const B175: &str = "01000000c052286e779e7e48397d8c39fee98a3a5718c82dd6bc5b71eebed8a700000000903bb52cc35576a52e9d8f35a901073d33145b6f7be16aab1aa328e8153dfb4874c46a49ffff001d227dd986";

    const TXID0_170: &str = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082";
    const TXID1_170: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

    fn chain_170() -> crate::chain::VerifiedChain {
        let headers: Vec<BlockHeader> = [B170, B171, B172, B173, B174, B175]
            .iter()
            .map(|h| BlockHeader::parse(&from_hex(h)).unwrap())
            .collect();
        verify_chain(&headers, 170, &BITCOIN).unwrap()
    }

    fn deposit_of(chain: &crate::chain::VerifiedChain) -> DepositProof<'_> {
        DepositProof {
            params: &BITCOIN,
            corridor_id: 0,
            chain,
            deposit_height: 170,
            txid: reversed(TXID0_170),
            branch: vec![MerkleStep {
                hash: reversed(TXID1_170),
                sibling_on_left: false,
            }],
            asset_id: *b"qBTC............",
            amount: 5_000_000_000u128,
            recipient: [0x42u8; 32],
        }
    }

    #[test]
    fn a_successful_verification_yields_a_stable_canonical_witness() {
        let chain = chain_170();
        let a = deposit_of(&chain).prove_ready_witness().unwrap();
        let b = deposit_of(&chain).prove_ready_witness().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn the_digest_matches_a_fresh_hash_of_the_statement_and_facts() {
        let chain = chain_170();
        let witness = deposit_of(&chain).prove_ready_witness().unwrap();
        assert_eq!(witness.public_input_digest, shake256_256(&witness.encode()));
    }

    #[test]
    fn the_witness_carries_the_statement_the_verification_produced() {
        let chain = chain_170();
        let witness = deposit_of(&chain).prove_ready_witness().unwrap();
        assert_eq!(witness.statement.corridor_id, 0);
        assert_eq!(witness.statement.finality_depth, 6);
        assert_eq!(witness.facts.deposit_height, 170);
        assert_eq!(witness.facts.deposit_block_hash, chain.header_at(170).unwrap().block_hash());
        assert_eq!(witness.facts.tip_height, chain.tip_height);
        assert_eq!(witness.facts.network_magic, BITCOIN.magic);
    }

    #[test]
    fn changing_the_amount_changes_the_witness_digest() {
        let chain = chain_170();
        let a = deposit_of(&chain).prove_ready_witness().unwrap();
        let mut proof = deposit_of(&chain);
        proof.amount += 1;
        let b = proof.prove_ready_witness().unwrap();
        assert_ne!(a.public_input_digest, b.public_input_digest);
    }

    #[test]
    fn a_deposit_short_of_the_confirmation_depth_yields_no_witness() {
        let headers: Vec<BlockHeader> = [B170, B171, B172]
            .iter()
            .map(|h| BlockHeader::parse(&from_hex(h)).unwrap())
            .collect();
        let chain = verify_chain(&headers, 170, &BITCOIN).unwrap();
        assert_eq!(
            deposit_of(&chain).prove_ready_witness(),
            Err(SpvError::InsufficientConfirmations { have: 3, need: 6 })
        );
    }

    #[test]
    fn the_encoded_witness_is_a_fixed_width_of_hash_and_count_fields_only() {
        let chain = chain_170();
        let witness = deposit_of(&chain).prove_ready_witness().unwrap();
        assert_eq!(
            witness.encode().len(),
            ProofStatement::ENCODED_LEN + BitcoinCheckedFacts::ENCODED_LEN
        );
    }

    #[test]
    fn the_digest_binds_the_checked_facts_not_only_the_statement() {
        let statement = bitcoin_spv(
            0,
            [0u8; 32],
            EventClaim {
                source_ref: [0x11u8; 32],
                asset_id: [0x22u8; 16],
                amount: 1,
                recipient: [0x33u8; 32],
            },
            6,
        );
        let facts_a = BitcoinCheckedFacts {
            network_magic: BITCOIN.magic,
            tip_height: 175,
            deposit_height: 170,
            deposit_block_hash: [0x44u8; 32],
            deposit_merkle_root: [0x55u8; 32],
        };
        let mut facts_b = facts_a;
        facts_b.deposit_block_hash[0] ^= 0xff;
        assert_ne!(digest_of(&statement, &facts_a), digest_of(&statement, &facts_b));
    }
}
