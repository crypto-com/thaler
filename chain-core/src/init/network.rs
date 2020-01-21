use std::sync::Once;
static INIT_NETWORK: Once = Once::new();
static INIT_NETWORK_ID: Once = Once::new();

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

/// Public testnet Chain ID (expected in Tendermint's genesis.json)
pub const TESTNET_CHAIN_ID: &str = "testnet-thaler-crypto-com-chain-42";
/// Mainnet Chain ID (expected in Tendermint's genesis.json)
pub const MAINNET_CHAIN_ID: &str = "mainnet-crypto-com-chain-2A";

/// One-time initialization of the chosen network
/// (as address textual format / serialization + HD-wallet path depend on the network type)
pub fn init_chain_id(chain_id_src: &str) {
    let chain_id = chain_id_src.to_string();
    assert!(chain_id.len() >= 6);
    let length = chain_id.len();
    let hexstring = &chain_id[(length - 2)..];
    let hexvalue = hex::decode(hexstring).expect("last two characters should be hex digits");
    assert!(1 == hexvalue.len());
    init_network_id(hexvalue[0]);
    assert!(get_network_id() == hexvalue[0]);

    match chain_id_src {
        MAINNET_CHAIN_ID => init_network(Network::Mainnet),
        TESTNET_CHAIN_ID => init_network(Network::Testnet),
        _ => init_network(Network::Devnet),
    }
}

fn init_network(network: Network) {
    unsafe {
        INIT_NETWORK.call_once(|| {
            chosen_network::NETWORK = network;
        });
    }
}

fn init_network_id(id: u8) {
    unsafe {
        INIT_NETWORK_ID.call_once(|| {
            chosen_network::NETWORK_ID = id;
        });
    }
}

/// Returns the identifier of the chosen network (a single byte included in transaction metadata)
pub fn get_network_id() -> u8 {
    unsafe { chosen_network::NETWORK_ID }
}

#[no_mangle]
/// Returns the chosen network type
pub extern "C" fn get_network() -> Network {
    unsafe { chosen_network::NETWORK }
}

/// Given the chosen network, it returns the human readable part of Bech32 address
pub fn get_bech32_human_part() -> &'static str {
    get_bech32_human_part_from_network(get_network())
}

/// Returns the human readable part of Bech32 address of the provided network
pub fn get_bech32_human_part_from_network(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "cro",
        Network::Testnet => "tcro",
        Network::Devnet => "dcro",
    }
}

/// Given the chosen network, it returns bip44 cointype
pub fn get_bip44_coin_type() -> u32 {
    get_bip44_coin_type_from_network(get_network())
}

/// Returns bip44 cointype of the provided network
/// 1         0x80000001             Testnet (all coins)
/// 394       0x8000018a     CRO     Crypto.com Chain
pub fn get_bip44_coin_type_from_network(network: Network) -> u32 {
    match network {
        Network::Mainnet => 394,
        Network::Testnet => 1,
        Network::Devnet => 1,
    }
}

mod chosen_network {
    use super::*;
    pub static mut NETWORK: Network = Network::Devnet;
    pub static mut NETWORK_ID: u8 = 0;
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn init_chain_id_should_setup_correctly() {
        init_chain_id("dev-chain-y3m1e6-AB");
        assert_eq!(0xab as u8, get_network_id());
        assert_eq!(Network::Devnet, get_network());
        assert_eq!("dcro", get_bech32_human_part());
        assert_eq!(1, get_bip44_coin_type());
    }

    #[test]
    fn get_bip44_coin_type_from_network_should_work() {
        assert_eq!(394, get_bip44_coin_type_from_network(Network::Mainnet));
        assert_eq!(1, get_bip44_coin_type_from_network(Network::Testnet));
        assert_eq!(1, get_bip44_coin_type_from_network(Network::Devnet));
    }
}
