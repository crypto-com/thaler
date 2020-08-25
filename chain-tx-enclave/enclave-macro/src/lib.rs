extern crate proc_macro;

use proc_macro::TokenStream;
#[proc_macro]
pub fn get_network_id(_input: TokenStream) -> TokenStream {
    format!("0x{}", env! {"NETWORK_ID"}).parse().unwrap()
}

#[proc_macro]
pub fn mock_key(_input: TokenStream) -> TokenStream {
    let random_bytes: [u8; 16] = rand::random();
    format!("{:?}", random_bytes).parse().unwrap()
}

#[inline]
fn get_32byte_from_hex(data: &str) -> TokenStream {
    let mrsigner: Vec<u8> = hex::decode(data).unwrap();
    if mrsigner.len() != 32 {
        panic!("mrsigner or mrenclave incorrect length");
    }
    format!("{:?}", mrsigner).parse().unwrap()
}

#[proc_macro]
pub fn get_mrsigner(_input: TokenStream) -> TokenStream {
    get_32byte_from_hex(env! {"MRSIGNER"})
}

#[proc_macro]
pub fn get_tqe_mrenclave(_input: TokenStream) -> TokenStream {
    get_32byte_from_hex(env! {"TQE_MRENCLAVE"})
}
