use std::sync::Once;
static INIT_NETWORK: Once = Once::new();
static INIT_NETWORK_ID: Once = Once::new();

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
}

pub fn init_chain_id(chain_id_src: &str) {
    let chain_id = chain_id_src.to_string();
    assert!(chain_id.len() > 6);
    let length = chain_id.len();
    let hexstring = &chain_id[(length - 2)..];
    let hexvalue = hex::decode(hexstring).unwrap();
    assert!(1 == hexvalue.len());
    init_network_id(hexvalue[0]);

    //main, test
    let kind = &chain_id[..4];
    if "main" == kind {
        init_network(Network::Mainnet);
    } else {
        init_network(Network::Testnet);
    }
}
pub fn init_network(network: Network) {
    unsafe {
        INIT_NETWORK.call_once(|| {
            NETWORK = network;
        });
    }
}

pub fn init_network_id(id: u8) {
    unsafe {
        INIT_NETWORK_ID.call_once(|| {
            NETWORK_ID = id;
        });
    }
}

pub fn get_network_id() -> u8 {
    unsafe { NETWORK_ID }
}

pub fn get_network() -> Network {
    unsafe { NETWORK }
}

pub fn get_bech32_human_part() -> &'static str {
    unsafe {
        match NETWORK {
            Network::Mainnet => "crmt",
            Network::Testnet => "crtt",
        }
    }
}

pub fn get_full_network_name() -> &'static str {
    unsafe {
        match NETWORK {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

static mut NETWORK: Network = Network::Mainnet;
static mut NETWORK_ID: u8 = 0 as u8;

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn init_chain_id_should_setup_correctly() {
        init_chain_id("main-chain-y3m1e6-AB");
        assert_eq!(0xab as u8, get_network_id());
        assert_eq!(Network::Mainnet, get_network());
    }
}
