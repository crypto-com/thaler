use std::env;
use std::process::Command;

fn main() {
    if let Ok(_) = env::var("CARGO_FEATURE_MESALOCK_SGX") {
        let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());

        #[cfg(target_arch = "x86")]
        let edger8r = format!("{}/bin/x86/sgx_edger8r", sdk_dir);
        #[cfg(not(target_arch = "x86"))]
        let edger8r = format!("{}/bin/x64/sgx_edger8r", sdk_dir);

        Command::new(edger8r)
            .args(&[
                "--trusted",
                "Enclave.edl",
                "--search-path",
                &format!("{}/include", sdk_dir),
                "--search-path",
                "../../rust-sgx-sdk/edl",
                "--trusted-dir",
                ".",
            ])
            .status()
            .unwrap();

        cc::Build::new()
            .file("Enclave_t.c")
            .include("../../rust-sgx-sdk/common/inc")
            .include("../../rust-sgx-sdk/edl")
            .include(&format!("{}/include", sdk_dir))
            .include(&format!("{}/include/tlibc", sdk_dir))
            .flag("-nostdinc")
            .flag("-fvisibility=hidden")
            .flag("-fpie")
            .flag("-fstack-protector")
            .compile("enclave.a");

        println!("cargo:rerun-if-changed=Enclave.edl");
    }
}
