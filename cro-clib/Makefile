all:
	cd ./examples && make
ios: ios_install ios_compile
ios_install:
	cargo install cargo-lipo
	rustup target add aarch64-apple-ios x86_64-apple-ios
ios_compile:
	cargo lipo -p cro-clib --release
