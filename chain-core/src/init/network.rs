use std::sync::Once;
static INIT_NETWORK: Once = Once::new();
static INIT_NETWORK_ID: Once = Once::new();

#[derive(Debug, Copy, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
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
    "bech32"
}

pub fn get_full_network_name() -> &'static str {
    "network"
}

static mut NETWORK: Network = Network::Mainnet;
static mut NETWORK_ID: u8 = 0 as u8;
