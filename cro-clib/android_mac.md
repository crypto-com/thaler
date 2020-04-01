## install android for mac
1. install android studio
2. install ndk, sdk(api 26)
3. locations as below  
```
sdk:  $HOME/Library/Android/sdk
ndK:  $HOME/Library/Android/sdk/ndk/21.0.6113669
```

## modify path 
to make it compatible with linux script  
```
ln -sf $HOME/Library/Android $HOME/Android
```

## make rust toolchain folder  
cross compiler will be copied here for rust  
```
mkdir -p $HOME/rust_android/NDK
```

## check folders
now folders are like below 
```
ANDROID_HOME: l$HOME/Android/Sdk
NDK_HOME: $ANDROID_HOME/ndk/21.0.6113669
RUST_ANDROID: $HOME/rust_android/NDK
```


## install openssl
install openssl   
```
brew install openssl@1.1
```

## go to folder
```
cd chain/cro-clib
```


## setup path
1. make setup file  
vi ./setup.sh  
2. write as below  
```
export ANDROID_HOME=$HOME/Library/Android/sdk
export NDK_HOME=$HOME/Library/Android/sdk/ndk/21.0.6113669
export RUST_ANDROID=$HOME/rust_android/NDK

export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"
export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.1/lib/pkgconfig"
```

## run setup
activate env variables setup
```
. ./setup.sh
```
now environment variables ready   


## run script
this will install android rust-toolchain and compile cbindings    
```
make android
```

## errors
1. cannot find -lssl , cannot find -lcrypto   
remove cdylib in crate-type, specify only `staticlib` in Cargo.toml  
```
crate-type =["staticlib"]
```

2. OPENSSL_DIR unset    
install openssl   
```
brew install openssl@1.1
```




