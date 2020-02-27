#!/bin/bash
export ANDROID_HOME=$HOME/Android/Sdk
export NDK_HOME=$ANDROID_HOME/ndk/21.0.6113669
export RUST_ANDROID=$HOME/rust_android/NDK
mkdir -p $RUST_ANDROID
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android
cd $RUST_ANDROID
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch arm64 --install-dir arm64 --force
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch arm --install-dir arm --force 
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch x86 --install-dir x86 --force
