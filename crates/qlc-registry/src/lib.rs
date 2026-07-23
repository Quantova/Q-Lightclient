#![forbid(unsafe_code)]

use qlc_core::{TrustGrade, VerificationTier};

pub const TARGET_CHAINS: usize = 36;
pub const TARGET_ASSETS: usize = 70;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corridor {
    pub chain_id: u32,
    pub name: &'static str,
    pub tier: VerificationTier,
    pub grade: TrustGrade,
    pub confirmation_depth: u32,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asset {
    pub origin_chain: u32,
    pub symbol: &'static str,
    pub tag: &'static str,
}

pub fn seed_corridors() -> Vec<Corridor> {
    vec![
        Corridor { chain_id: 0, name: "Bitcoin", tier: VerificationTier::Spv, grade: TrustGrade::NearTrustless, confirmation_depth: 6, active: true },
        Corridor { chain_id: 1, name: "Ethereum", tier: VerificationTier::LightClient, grade: TrustGrade::ProvenLightClient, confirmation_depth: 64, active: true },
        Corridor { chain_id: 2, name: "BNB Smart Chain", tier: VerificationTier::LightClient, grade: TrustGrade::ProvenLightClient, confirmation_depth: 15, active: true },
        Corridor { chain_id: 3, name: "Solana", tier: VerificationTier::Federated, grade: TrustGrade::Relayer, confirmation_depth: 32, active: true },
        Corridor { chain_id: 4, name: "TRON", tier: VerificationTier::Federated, grade: TrustGrade::Relayer, confirmation_depth: 19, active: true },
        Corridor { chain_id: 5, name: "Polygon", tier: VerificationTier::LightClient, grade: TrustGrade::ProvenLightClient, confirmation_depth: 128, active: true },
        Corridor { chain_id: 6, name: "Arbitrum", tier: VerificationTier::LightClient, grade: TrustGrade::ProvenLightClient, confirmation_depth: 64, active: true },
        Corridor { chain_id: 7, name: "Base", tier: VerificationTier::LightClient, grade: TrustGrade::ProvenLightClient, confirmation_depth: 64, active: true },
        Corridor { chain_id: 8, name: "Cosmos Hub", tier: VerificationTier::LightClient, grade: TrustGrade::ProvenLightClient, confirmation_depth: 2, active: true },
    ]
}

pub fn seed_assets() -> Vec<Asset> {
    vec![
        Asset { origin_chain: 0, symbol: "BTC", tag: "qBTC.btc" },
        Asset { origin_chain: 1, symbol: "ETH", tag: "qETH.eth" },
        Asset { origin_chain: 1, symbol: "USDT", tag: "qUSDT.eth" },
        Asset { origin_chain: 1, symbol: "USDC", tag: "qUSDC.eth" },
        Asset { origin_chain: 1, symbol: "LINK", tag: "qLINK.eth" },
        Asset { origin_chain: 1, symbol: "SHIB", tag: "qSHIB.eth" },
        Asset { origin_chain: 1, symbol: "UNI", tag: "qUNI.eth" },
        Asset { origin_chain: 2, symbol: "USDT", tag: "qUSDT.bsc" },
        Asset { origin_chain: 2, symbol: "BNB", tag: "qBNB.bsc" },
        Asset { origin_chain: 2, symbol: "LINK", tag: "qLINK.bsc" },
        Asset { origin_chain: 2, symbol: "FDUSD", tag: "qFDUSD.bsc" },
        Asset { origin_chain: 2, symbol: "TUSD", tag: "qTUSD.bsc" },
        Asset { origin_chain: 3, symbol: "USDT", tag: "qUSDT.sol" },
        Asset { origin_chain: 3, symbol: "SOL", tag: "qSOL.sol" },
        Asset { origin_chain: 3, symbol: "USDC", tag: "qUSDC.sol" },
        Asset { origin_chain: 3, symbol: "RENDER", tag: "qRENDER.sol" },
        Asset { origin_chain: 3, symbol: "BONK", tag: "qBONK.sol" },
        Asset { origin_chain: 3, symbol: "WIF", tag: "qWIF.sol" },
        Asset { origin_chain: 4, symbol: "USDT", tag: "qUSDT.tron" },
        Asset { origin_chain: 4, symbol: "TRX", tag: "qTRX.tron" },
        Asset { origin_chain: 4, symbol: "TUSD", tag: "qTUSD.tron" },
        Asset { origin_chain: 4, symbol: "XAUT", tag: "qXAUT.tron" },
        Asset { origin_chain: 5, symbol: "USDT", tag: "qUSDT.poly" },
        Asset { origin_chain: 5, symbol: "USDC", tag: "qUSDC.poly" },
        Asset { origin_chain: 5, symbol: "LINK", tag: "qLINK.poly" },
        Asset { origin_chain: 5, symbol: "UNI", tag: "qUNI.poly" },
        Asset { origin_chain: 5, symbol: "AAVE", tag: "qAAVE.poly" },
        Asset { origin_chain: 5, symbol: "POL", tag: "qPOL.poly" },
        Asset { origin_chain: 6, symbol: "ETH", tag: "qETH.arb" },
        Asset { origin_chain: 6, symbol: "USDT", tag: "qUSDT.arb" },
        Asset { origin_chain: 6, symbol: "USDC", tag: "qUSDC.arb" },
        Asset { origin_chain: 6, symbol: "LINK", tag: "qLINK.arb" },
        Asset { origin_chain: 6, symbol: "UNI", tag: "qUNI.arb" },
        Asset { origin_chain: 6, symbol: "AAVE", tag: "qAAVE.arb" },
        Asset { origin_chain: 7, symbol: "ETH", tag: "qETH.base" },
        Asset { origin_chain: 7, symbol: "USDC", tag: "qUSDC.base" },
        Asset { origin_chain: 7, symbol: "LINK", tag: "qLINK.base" },
        Asset { origin_chain: 7, symbol: "AERO", tag: "qAERO.base" },
        Asset { origin_chain: 7, symbol: "VIRTUAL", tag: "qVIRTUAL.base" },
        Asset { origin_chain: 7, symbol: "wstETH", tag: "qwstETH.base" },
        Asset { origin_chain: 8, symbol: "ATOM", tag: "qATOM.atom" },
    ]
}

pub fn corridor(chain_id: u32) -> Option<Corridor> {
    seed_corridors().into_iter().find(|c| c.chain_id == chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_seed_corridor_declares_a_confirmation_depth() {
        for c in seed_corridors() {
            assert!(c.confirmation_depth > 0, "corridor {} has no finality depth", c.name);
        }
    }

    #[test]
    fn bitcoin_is_graded_near_trustless() {
        let btc = corridor(0).unwrap();
        assert_eq!(btc.grade, TrustGrade::NearTrustless);
    }

    #[test]
    fn assets_are_origin_tagged_and_unique() {
        let assets = seed_assets();
        let tags: BTreeSet<&str> = assets.iter().map(|a| a.tag).collect();
        assert_eq!(tags.len(), assets.len());
    }

    #[test]
    fn same_symbol_on_two_chains_is_two_distinct_assets() {
        let assets = seed_assets();
        let usdt: Vec<&Asset> = assets.iter().filter(|a| a.symbol == "USDT").collect();
        assert!(usdt.len() >= 5);
        let tags: BTreeSet<&str> = usdt.iter().map(|a| a.tag).collect();
        assert_eq!(tags.len(), usdt.len());
    }

    #[test]
    fn seed_stays_within_the_target_envelope() {
        assert!(seed_corridors().len() <= TARGET_CHAINS);
        assert!(seed_assets().len() <= TARGET_ASSETS);
    }
}
