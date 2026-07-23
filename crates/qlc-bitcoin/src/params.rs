#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    BitcoinCash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkParams {
    pub network: Network,
    pub name: &'static str,
    pub magic: [u8; 4],
    pub pow_limit_bits: u32,
    pub target_timespan: u32,
    pub target_spacing: u32,
    pub confirmation_depth: u32,
}

impl NetworkParams {
    pub fn retarget_interval(&self) -> u32 {
        self.target_timespan / self.target_spacing
    }
}

pub const BITCOIN: NetworkParams = NetworkParams {
    network: Network::Bitcoin,
    name: "Bitcoin",
    magic: [0xf9, 0xbe, 0xb4, 0xd9],
    pow_limit_bits: 0x1d00ffff,
    target_timespan: 1_209_600,
    target_spacing: 600,
    confirmation_depth: 6,
};

pub const BITCOIN_CASH: NetworkParams = NetworkParams {
    network: Network::BitcoinCash,
    name: "Bitcoin Cash",
    magic: [0xe3, 0xe1, 0xf3, 0xe8],
    pow_limit_bits: 0x1d00ffff,
    target_timespan: 1_209_600,
    target_spacing: 600,
    confirmation_depth: 10,
};

pub fn network_params(network: Network) -> NetworkParams {
    match network {
        Network::Bitcoin => BITCOIN,
        Network::BitcoinCash => BITCOIN_CASH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_network_retargets_every_two_thousand_and_sixteen_blocks() {
        assert_eq!(BITCOIN.retarget_interval(), 2016);
        assert_eq!(BITCOIN_CASH.retarget_interval(), 2016);
    }

    #[test]
    fn both_networks_share_the_sha256d_proof_of_work_limit() {
        assert_eq!(BITCOIN.pow_limit_bits, BITCOIN_CASH.pow_limit_bits);
        assert_eq!(BITCOIN.target_timespan, BITCOIN_CASH.target_timespan);
        assert_eq!(BITCOIN.target_spacing, BITCOIN_CASH.target_spacing);
    }

    #[test]
    fn the_two_networks_are_distinct() {
        assert_ne!(BITCOIN.network, BITCOIN_CASH.network);
        assert_ne!(BITCOIN.magic, BITCOIN_CASH.magic);
        assert_ne!(BITCOIN.confirmation_depth, BITCOIN_CASH.confirmation_depth);
    }

    #[test]
    fn network_lookup_returns_the_matching_parameters() {
        assert_eq!(network_params(Network::Bitcoin), BITCOIN);
        assert_eq!(network_params(Network::BitcoinCash), BITCOIN_CASH);
    }
}
