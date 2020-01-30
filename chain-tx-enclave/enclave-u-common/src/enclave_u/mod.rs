//! Copyright (c) 2017-2020 Apache Teaclave Authors (licensed under the Apache License, Version 2.0)
//!
//! Modifications Copyright 2018-2020 Foris Limited (licensed under the Apache License, Version 2.0)

use sgx_types::*;
use sgx_urts::SgxEnclave;

/// returns the initialized enclave
pub fn init_enclave(name: &str, debug: bool) -> SgxResult<SgxEnclave> {
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = if debug { 1 } else { 0 };
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    // TODO: remove the launch token-related args when they are removed from SDK
    SgxEnclave::create(name, debug, &mut [0; 1024], &mut 0, &mut misc_attr)
}
