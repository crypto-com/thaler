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

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

/// returns the initialized enclave
pub fn init_enclave(debug: bool) -> SgxResult<SgxEnclave> {
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = if debug { 1 } else { 0 };
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    // TODO: remove the launch token-related args when they are removed from SDK
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut [0; 1024],
        &mut 0,
        &mut misc_attr,
    )
}
