// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::chain::{ConfirmedDeposit, VerifiedChain};
use crate::params::NetworkParams;
use crate::{MerkleStep, SpvError};
use qlc_stark::corridors::{bitcoin_spv, EventClaim, ProofStatement};
use qlc_stark::shake256_256;
use qlc_stark::StarkStatement;

pub struct DepositProof<'a> {
    pub params: &'a NetworkParams,
    pub corridor_id: u32,
    pub chain: &'a VerifiedChain,
    pub deposit_height: u32,
    pub txid: [u8; 32],
    pub branch: Vec<MerkleStep>,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub recipient: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenDeposit {
    pub confirmed: ConfirmedDeposit,
    pub statement: ProofStatement,
    pub lowered: StarkStatement,
}

impl<'a> DepositProof<'a> {
    fn public_input_digest(
        &self,
        statement: &ProofStatement,
        confirmed: &ConfirmedDeposit,
    ) -> [u8; 32] {
        let mut buf = statement.encode();
        buf.extend_from_slice(&self.params.magic);
        buf.extend_from_slice(&self.chain.tip_height.to_le_bytes());
        buf.extend_from_slice(&confirmed.block_hash);
        buf.extend_from_slice(&confirmed.deposit_height.to_le_bytes());
        buf.extend_from_slice(&confirmed.merkle_root);
        shake256_256(&buf)
    }

    pub fn prove(&self) -> Result<ProvenDeposit, SpvError> {
        let confirmed = self.chain.verify_deposit(
            self.deposit_height,
            self.txid,
            &self.branch,
            self.params.confirmation_depth,
        )?;
        let event = EventClaim {
            source_ref: self.txid,
            asset_id: self.asset_id,
            amount: self.amount,
            recipient: self.recipient,
        };
        let statement = bitcoin_spv(
            self.corridor_id,
            self.chain.tip_hash,
            event,
            confirmed.confirmations,
        );
        let digest = self.public_input_digest(&statement, &confirmed);
        let lowered = statement.to_stark_statement(digest);
        Ok(ProvenDeposit {
            confirmed,
            statement,
            lowered,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_chain;
    use crate::params::BITCOIN;
    use crate::BlockHeader;
    use qlc_stark::corridors::is_proof_corridor;
    use qlc_stark::StatementKind;

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

    fn chain_170() -> VerifiedChain {
        let headers: Vec<BlockHeader> = [B170, B171, B172, B173, B174, B175]
            .iter()
            .map(|h| BlockHeader::parse(&from_hex(h)).unwrap())
            .collect();
        verify_chain(&headers, 170, &BITCOIN).unwrap()
    }

    fn deposit_of<'a>(chain: &'a VerifiedChain) -> DepositProof<'a> {
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
    fn a_verified_deposit_feeds_a_bitcoin_spv_statement() {
        let chain = chain_170();
        let proven = deposit_of(&chain).prove().unwrap();
        assert_eq!(proven.statement.kind, StatementKind::BitcoinSpv);
        assert!(is_proof_corridor(proven.statement.kind));
        assert_eq!(proven.lowered.kind, StatementKind::BitcoinSpv);
    }

    #[test]
    fn the_statement_carries_the_tip_as_its_anchor_and_the_confirmation_count() {
        let chain = chain_170();
        let proven = deposit_of(&chain).prove().unwrap();
        assert_eq!(proven.statement.anchor, chain.tip_hash);
        assert_eq!(proven.statement.finality_depth, 6);
        assert_eq!(proven.confirmed.confirmations, 6);
    }

    #[test]
    fn the_amount_is_carried_in_base_units() {
        let chain = chain_170();
        let proven = deposit_of(&chain).prove().unwrap();
        assert_eq!(proven.statement.event.amount, 5_000_000_000u128);
    }

    #[test]
    fn the_lowered_statement_round_trips_across_the_airlock_width() {
        let chain = chain_170();
        let proven = deposit_of(&chain).prove().unwrap();
        let bytes = proven.lowered.encode();
        assert_eq!(StarkStatement::decode(&bytes), Some(proven.lowered));
    }

    #[test]
    fn changing_the_amount_changes_the_public_input_digest() {
        let chain = chain_170();
        let a = deposit_of(&chain).prove().unwrap();
        let mut proof = deposit_of(&chain);
        proof.amount += 1;
        let b = proof.prove().unwrap();
        assert_ne!(a.lowered.public_input_digest, b.lowered.public_input_digest);
    }

    #[test]
    fn changing_the_recipient_changes_the_public_input_digest() {
        let chain = chain_170();
        let a = deposit_of(&chain).prove().unwrap();
        let mut proof = deposit_of(&chain);
        proof.recipient = [0x43u8; 32];
        let b = proof.prove().unwrap();
        assert_ne!(a.lowered.public_input_digest, b.lowered.public_input_digest);
    }

    #[test]
    fn a_deposit_short_of_the_confirmation_depth_produces_no_statement() {
        let headers: Vec<BlockHeader> = [B170, B171, B172]
            .iter()
            .map(|h| BlockHeader::parse(&from_hex(h)).unwrap())
            .collect();
        let chain = verify_chain(&headers, 170, &BITCOIN).unwrap();
        let result = deposit_of(&chain).prove();
        assert_eq!(
            result,
            Err(SpvError::InsufficientConfirmations { have: 3, need: 6 })
        );
    }
}
