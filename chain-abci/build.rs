use std::env;
use std::path::Path;
use std::process::Command;
use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    let mut flags = ConstantsFlags::empty();
    flags.toggle(ConstantsFlags::BUILD_DATE);
    flags.toggle(ConstantsFlags::SHA_SHORT);

    generate_cargo_keys(flags).expect("Unable to generate the cargo keys!");

    match env::var("CARGO_CFG_TARGET_OS").as_ref() {
        Ok(os) if os == "linux" => {
            let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
            if !Path::new(&sdk_dir).exists() {
                println!("cargo:warning=\"SGX SDK not found\"");
            } else {
                let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

                #[cfg(target_arch = "x86")]
                let edger8r = format!("{}/bin/x86/sgx_edger8r", sdk_dir);
                #[cfg(not(target_arch = "x86"))]
                let edger8r = format!("{}/bin/x64/sgx_edger8r", sdk_dir);

                Command::new(edger8r)
                    .args(&[
                        "--untrusted",
                        "../chain-tx-enclave/tx-validation/enclave/Enclave.edl",
                        "--search-path",
                        &format!("{}/include", sdk_dir),
                        "--search-path",
                        "../chain-tx-enclave/rust-sgx-sdk/edl",
                        "--untrusted-dir",
                        ".",
                    ])
                    .status()
                    .unwrap();

                cc::Build::new()
                    .file("Enclave_u.c")
                    .include(&format!("{}/include", sdk_dir))
                    .include("../chain-tx-enclave/rust-sgx-sdk/edl")
                    .compile("enclave.a");

                #[cfg(target_arch = "x86")]
                println!("cargo:rustc-link-search=native={}/lib", sdk_dir);
                #[cfg(not(target_arch = "x86"))]
                println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);

                match is_sim.as_ref() {
                    "SW" => println!("cargo:rustc-link-lib=dylib=sgx_urts_sim"),
                    _ => println!("cargo:rustc-link-lib=dylib=sgx_urts"), // default to HW
                }

                println!(
                    "cargo:rerun-if-changed=../chain-tx-enclave/tx-validation/enclave/Enclave.edl"
                );
            }
        }
        _ => {
            println!(
                "cargo:warning=\"Enclave compilation and execution is only supported on Linux\""
            );
        }
    }
}
