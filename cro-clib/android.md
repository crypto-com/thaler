# c-bindings on android

## prepare
1. install android studio  
2. run android studio  
3. install ndk in sdk-manager  

## modify ubuntu
```
sudo apt install qemu-kvm
sudo usermod -aG kvm $USER
```

## setup
```
export ANDROID_HOME=$HOME/Android/Sdk
export NDK_HOME=$ANDROID_HOME/ndk/21.0.6113669
export RUST_ANDROID=$HOME/rust_android/NDK
```

## for simple compile
```
make android
```
for manual compilation, refer to below

## build rust android
1. mkdir -p $RUST_ANDROID
2. cd $RUST_ANDROID
3. run 
```
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch arm64 --install-dir arm64
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch arm --install-dir arm
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch x86 --install-dir x86
```

## target add
```
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android
```

## setup ssl and cross-compile 
```
sudo apt-get install libssl1.0-dev
export PKG_CONFIG_ALLOW_CROSS=1 
export CFLAGS=-D__ANDROID_API__=26
export PATH=$RUST_ANDROID/arm/bin:$RUST_ANDROID/arm64/bin:$RUST_ANDROID/x86/bin:$PATH
```


## build
```
cargo build -p cro-clib --target aarch64-linux-android --release
cargo build -p cro-clib --target  i686-linux-android --release
```

