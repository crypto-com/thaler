all: build run
build:
	cargo build
	gcc -g test.c tx.c rpc.c -o cro -lcro_clib -lssl -lm -lcrypto -ldl -lpthread -L../../target/debug/ -lrocksdb -lstdc++
run:
	LD_LIBRARY_PATH=../../target/debug ./cro
mac: mac_build run
mac_build:
	cargo build
	gcc -g test.c tx.c rpc.c -o cro -lcro_clib  -L../../target/debug/

mac: mac_build run 
mac_build:
	cargo build
	gcc -g test.c tx.c rpc.c -o cro -lcro_clib -L../../target/debug/


