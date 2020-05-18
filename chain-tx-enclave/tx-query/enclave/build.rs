use std::env;
use std::process::Command;

fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());

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

    let mut build = cc::Build::new();

    build
        .file("Enclave_t.c")
        .include("../../rust-sgx-sdk/common/inc")
        .include("../../rust-sgx-sdk/edl")
        .include(&format!("{}/include", sdk_dir))
        .include(&format!("{}/include/tlibc", sdk_dir))
        .opt_level(2)
        .flag("-fstack-protector")
        .flag("-ffreestanding")
        .flag("-fpie")
        .flag("-fno-strict-overflow")
        .flag("-fno-delete-null-pointer-checks")
        .flag("-fvisibility=hidden");

    let mitigation_cflags1 = "-mindirect-branch-register";
    let mitigation_cflags2 = "-mfunction-return=thunk-extern";
    let mitigation_asflags = "-fno-plt";
    let mitigation_loadflags1 = "-Wa,-mlfence-after-load=yes";
    let mitigation_loadflags2 = "-Wa,-mlfence-before-ret=not";
    let mitigation_cfflags1 = "-Wa,-mlfence-before-indirect-branch=register";
    let mitigation_cfflags2 = "-Wa,-mlfence-before-ret=not";
    let mitigation = env::var("MITIGATION_CVE_2020_0551").unwrap_or("LOAD".to_owned());
    match mitigation.as_ref() {
        "LOAD" => {
            build
                .flag(mitigation_cflags1)
                .flag(mitigation_cflags2)
                .flag(mitigation_asflags)
                .flag(mitigation_loadflags1)
                .flag(mitigation_loadflags2);
        }
        "CF" => {
            build
                .flag(mitigation_cflags1)
                .flag(mitigation_cflags2)
                .flag(mitigation_asflags)
                .flag(mitigation_cfflags1)
                .flag(mitigation_cfflags2);
        }
        _ => {}
    }

    build.compile("enclave.a");

    println!("cargo:rerun-if-changed=Enclave.edl");
}
