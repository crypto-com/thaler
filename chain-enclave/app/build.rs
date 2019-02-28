use std::env;

fn main () {

    let sdk_dir = env::var("SGX_SDK")
                    .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    let is_sim = env::var("SGX_MODE")
                    .unwrap_or_else(|_| "SW".to_string());
    let proj_path = env::var("PROJ_PATH").unwrap_or("/root/chain/chain-enclave".to_string());
    println!("cargo:rustc-link-search=native={}/lib", proj_path);
    println!("cargo:rustc-link-lib=static=Enclave_u");

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    match is_sim.as_ref() {
        "SW" => {
		println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
		println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
		},
        _    => { // Treat both HW and undefined as HW
		println!("cargo:rustc-link-lib=dylib=sgx_urts");
		println!("cargo:rustc-link-lib=dylib=sgx_uae_service");	
		},
    }
}
