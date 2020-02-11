all:
	cargo build
	gcc -g test.c tx.c -o cro -lcro_clib  -L../../target/debug/
	LD_LIBRARY_PATH=../../target/debug ./cro
