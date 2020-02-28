#!/bin/bash
export PKG_CONFIG_ALLOW_CROSS=1 
export CFLAGS=-D__ANDROID_API__=26
export PATH=$RUST_ANDROID/arm/bin:$RUST_ANDROID/arm64/bin:$RUST_ANDROID/x86/bin:$PATH
cargo build -p cro-clib --target aarch64-linux-android --release
cargo build -p cro-clib --target  i686-linux-android --release
