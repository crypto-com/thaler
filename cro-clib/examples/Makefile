all: run
	cargo build
	gcc -g test.c tx.c rpc.c -o cro -lcro_clib -lssl -lm -lcrypto -ldl -lpthread -L../../target/debug/
run:
	LD_LIBRARY_PATH=../../target/debug ./cro
