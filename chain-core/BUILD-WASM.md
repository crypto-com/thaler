WASM BUILD GUIDE
----------------------------

## install emcc for compile WASM
1. use ubuntu 18.x
2. git clone https://github.com/emscripten-core/emsdk.git
3. cd emsdk
4. ./emsdk install latest
5. ./emsdk activate latest
6. source ./emsdk_env.sh


## for mac only
1. brew install llvm
2. source setup.sh
3. setup.sh is like below
```
export PATH="/usr/local/opt/llvm/bin:$PATH"
export LDFLAGS="-L/usr/local/opt/llvm/lib"
export CPPFLAGS="-I/usr/local/opt/llvm/include"
export LLVM="/usr/local/opt/llvm/bin"
export BINARYEN="/usr/local/opt/binaryen/bin"
```
4. source ./setup.sh   


## check toolchain is OK
emcc -v

## install target  
rustup target add wasm32-unknown-emscripten

## build
1. cargo build --target=wasm32-unknown-emscripten
2. cd target/wasm32-unknown-emscripten/debug/

## run wasm
```
node hello.js
```
## to build wasm file  
src/main.rs is necessary to build `WASM` file


## how to build chain-core sample
$HOME/chain is the chain location
1. cd $HOME/chain/chain-core
2. vi main.rs
```
use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::witness::tree::RawXOnlyPubkey;
use chain_core::tx::TransactionId;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::schnorrsig::schnorr_sign;
use secp256k1::{key::XOnlyPublicKey, Message, Secp256k1};

fn main() {
    let mut tx = Tx::new();
    tx.add_input(TxoPointer::new([0x01; 32], 1));
    tx.add_output(TxOut::new(ExtendedAddr::OrTree([0xbb; 32]), Coin::unit()));
    let secp = Secp256k1::new();
    let sk1 = SecretKey::from_slice(&[0xcc; 32][..]).expect("secret key");
    let pk1 = PublicKey::from_secret_key(&secp, &sk1);
    let raw_pk1 = RawXOnlyPubkey::from(XOnlyPublicKey::from_pubkey(&pk1).0.serialize());
    println!("pubkey: {:?}", raw_pk1);
    let msg = Message::from_slice(&tx.id()).expect("msg");
    let sig = schnorr_sign(&secp, &msg, &sk1);
    println!("signature: {:?}", sig);
}
```
3. cargo build --target=wasm32-unknown-emscripten --no-default-features
4. ls -la ../target/wasm32-unknown-emscripten/debug/*.wasm
```
../target/wasm32-unknown-emscripten/debug/chain_core.wasm
```

## run the WASM
1. cd ../target/wasm32-unknown-emscripten/debug/
2. node chain-core.js
```
pubkey: RawXOnlyPubkey([185, 92, ..., 153])
signature: a978f4f....848f
```
3. you can confirm that WASM is working
   

## common compile errors
1. secp256k1 build fail
```
error: failed to run custom build command for `secp256k1zkp v0.13.0 

Caused by:
  process didn't exit successfully: `...build-script-build` (exit code: 1)
--- stdout
TARGET = Some("wasm32-unknown-emscripten")
OPT_LEVEL = Some("0")
HOST = Some("x86_64-apple-darwin")
CC_wasm32-unknown-emscripten = None
CC_wasm32_unknown_emscripten = None
TARGET_CC = None
CC = None
```
setup again for emsdk
cd `your emsdk folder`
`source ./emsdk_env.sh`
2. `ring` build fail (in macosx)
you can find exact ring folder in logs, move to that folder
vi rand.rs
change `wasm32-unknown-unknown` to `wasm32-unkown-emscripten`
also add `web-sys` crate in dependency


