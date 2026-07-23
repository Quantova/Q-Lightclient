#![forbid(unsafe_code)]

pub mod corridors;
pub mod sha3;

pub use sha3::sha3_256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    BitcoinSpv,
    HeaderChain,
    LightClientStep,
    EvmLightClient,
    CosmosTendermint,
}

impl StatementKind {
    pub fn tag(self) -> u8 {
        match self {
            StatementKind::BitcoinSpv => 1,
            StatementKind::HeaderChain => 2,
            StatementKind::LightClientStep => 3,
            StatementKind::EvmLightClient => 4,
            StatementKind::CosmosTendermint => 5,
        }
    }

    pub fn from_tag(tag: u8) -> Option<StatementKind> {
        match tag {
            1 => Some(StatementKind::BitcoinSpv),
            2 => Some(StatementKind::HeaderChain),
            3 => Some(StatementKind::LightClientStep),
            4 => Some(StatementKind::EvmLightClient),
            5 => Some(StatementKind::CosmosTendermint),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkStatement {
    pub corridor_id: u32,
    pub kind: StatementKind,
    pub public_input_digest: [u8; 32],
}

impl StarkStatement {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.push(self.kind.tag());
        out.extend_from_slice(&self.corridor_id.to_le_bytes());
        out.extend_from_slice(&self.public_input_digest);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<StarkStatement> {
        if bytes.len() != 37 {
            return None;
        }
        let kind = StatementKind::from_tag(bytes[0])?;
        let corridor_id = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let mut public_input_digest = [0u8; 32];
        public_input_digest.copy_from_slice(&bytes[5..37]);
        Some(StarkStatement {
            corridor_id,
            kind,
            public_input_digest,
        })
    }
}

pub trait StarkProver {
    fn prove(&self, statement: &StarkStatement) -> Vec<u8>;
}

pub trait StarkVerifier {
    fn verify(&self, statement: &StarkStatement, proof: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_round_trips() {
        let s = StarkStatement {
            corridor_id: 1,
            kind: StatementKind::LightClientStep,
            public_input_digest: [7u8; 32],
        };
        let bytes = s.encode();
        assert_eq!(StarkStatement::decode(&bytes), Some(s));
    }

    #[test]
    fn unknown_kind_tag_does_not_decode() {
        let mut bytes = vec![9u8];
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        assert_eq!(StarkStatement::decode(&bytes), None);
    }
}
