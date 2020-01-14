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
