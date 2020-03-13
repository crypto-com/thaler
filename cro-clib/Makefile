all:
	cd ./examples && make
ios: ios_sample ios_install ios_compile ios_copy
ios_sample:
	./download_ios.sh
ios_install:
	cargo install cargo-lipo
	rustup target add aarch64-apple-ios x86_64-apple-ios
ios_compile:
	cargo lipo -p cro-clib --release
ios_copy:
	cp ./chain.h ./examples/sample-chain-ios-example/IosSample/IosSample
	cp ./chain-core.h ./examples/sample-chain-ios-example/IosSample/IosSample
	cp ../target/universal/release/libcro_clib.a  ./examples/sample-chain-ios-example/IosSample/IosSample
android: android_install  android_compile
android_install:
	./android_install.sh
android_compile:
	./android_compile.sh
