// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Modifications Copyright 2019 Foris Limited (licensed under the Apache License, Version 2.0)

use sgx_types::*;
use sgx_urts::SgxEnclave;

use log::{info, warn};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

pub const VALIDATION_TOKEN_KEY: &[u8] = b"tx-validation-enclave.token";
pub const QUERY_TOKEN_KEY: &[u8] = b"tx-query-enclave.token";

pub const TOKEN_LEN: usize = 1024;

/// returns the initialized enclave and the launch token (if it was created or updated)
pub fn init_enclave(debug: bool, previous_token: Option<Vec<u8>>) -> (SgxResult<SgxEnclave>, Option<sgx_launch_token_t>) {
    let mut launch_token: sgx_launch_token_t = [0; TOKEN_LEN];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in the key-value db */
    let stored_token = match previous_token {
        Some(token) => {
            info!("[+] Open token file success! ");
            if token.len() != TOKEN_LEN {
                warn!(
                    "[+] Token file invalid, will create new token file -- size: {} (expected {})",
                    token.len(),
                    TOKEN_LEN
                );
                false
            } else {
                launch_token.copy_from_slice(&token);
                true
            }
        }
        _ => {
            warn!("[-] Open token file error or not found! Will create one.");
            false
        }
    };

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = if debug { 1 } else { 0 };
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    let enclave = SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    );

    // Step 3: save the launch token if it is updated
    if (stored_token && launch_token_updated != 0) || !stored_token {
        (enclave, Some(launch_token))
    } else {
        (enclave, None)
    }

    
}
