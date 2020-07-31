use std::env;
use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    let mut flags = ConstantsFlags::empty();
    flags.toggle(ConstantsFlags::BUILD_DATE);
    flags.toggle(ConstantsFlags::SHA_SHORT);

    generate_cargo_keys(flags).expect("Unable to generate the cargo keys!");

    match env::var("CARGO_CFG_TARGET_OS").as_ref() {
        Ok(os) if os == "linux" => {
            // no special compilation
        }
        _ => {
            // TODO: windows should also work with EDP
            println!(
                "cargo:warning=\"Enclave compilation and execution is only supported on Linux\""
            );
        }
    }
}
