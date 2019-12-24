use std::env;
use std::process::Command;

fn main() {
    if let Ok(_) = env::var("CARGO_FEATURE_MESALOCK_SGX") {
        let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
        let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "SW".to_string());

        #[cfg(target_arch = "x86")]
        let edger8r = format!("{}/bin/x86/sgx_edger8r", sdk_dir);
        #[cfg(not(target_arch = "x86"))]
        let edger8r = format!("{}/bin/x64/sgx_edger8r", sdk_dir);

        Command::new(edger8r)
            .args(&[
                "--untrusted",
                "../enclave/Enclave.edl",
                "--search-path",
                &format!("{}/include", sdk_dir),
                "--search-path",
                "../../rust-sgx-sdk/edl",
                "--untrusted-dir",
                ".",
            ])
            .status()
            .unwrap();

        cc::Build::new()
            .file("Enclave_u.c")
            .include(&format!("{}/include", sdk_dir))
            .include("../../rust-sgx-sdk/edl")
            .compile("enclave.a");

        #[cfg(target_arch = "x86")]
        println!("cargo:rustc-link-search=native={}/lib", sdk_dir);
        #[cfg(not(target_arch = "x86"))]
        println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);

        match is_sim.as_ref() {
            "SW" => println!("cargo:rustc-link-lib=dylib=sgx_urts_sim"),
            _ => println!("cargo:rustc-link-lib=dylib=sgx_urts"), // default to SW
        }

        println!("cargo:rerun-if-changed=../enclave/Enclave.edl");
    }
}
