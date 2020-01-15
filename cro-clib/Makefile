all:
	cargo build
	gcc -g main.c -o cro -lcro_clib -L../target/debug/
	LD_LIBRARY_PATH=../target/debug ./cro
