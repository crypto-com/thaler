use std::sync::Once;
static INIT_NETWORK: Once = Once::new();
static INIT_NETWORK_ID: Once = Once::new();

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
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
    } else if "test" == kind {
        init_network(Network::Testnet);
    } else {
        init_network(Network::Devnet);
    }
}
pub fn init_network(network: Network) {
    unsafe {
        INIT_NETWORK.call_once(|| {
            chosen_network::NETWORK = network;
        });
    }
}

pub fn init_network_id(id: u8) {
    unsafe {
        INIT_NETWORK_ID.call_once(|| {
            chosen_network::NETWORK_ID = id;
        });
    }
}

pub fn get_network_id() -> u8 {
    unsafe { chosen_network::NETWORK_ID }
}

pub fn get_network() -> Network {
    unsafe { chosen_network::NETWORK }
}

pub fn get_bech32_human_part() -> &'static str {
    unsafe {
        match chosen_network::NETWORK {
            Network::Mainnet => "cro",
            Network::Testnet => "tcro",
            Network::Devnet => "dcro",
        }
    }
}

pub fn get_full_network_name() -> &'static str {
    unsafe {
        match chosen_network::NETWORK {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Devnet => "devnet",
        }
    }
}

mod chosen_network {
    use super::*;
    pub static mut NETWORK: Network = Network::Mainnet;
    pub static mut NETWORK_ID: u8 = 0 as u8;
}

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
