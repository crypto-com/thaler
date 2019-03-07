extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro]
pub fn get_network_id(_input: TokenStream) -> TokenStream {
    format!("0x{}", env! {"NETWORK_ID"}).parse().unwrap()
}
