all: compile prepare_jni compile_so run

prepare_jni:	
	javah -jni CroBindings

compile_so:
	gcc javalib.c CroBindings.c  -I /usr/lib/jvm/default-java/include -I /usr/lib/jvm/java-11-openjdk-amd64/include/linux -shared -fPIC -o libCroBindings.so -lcro_clib -lssl -lm -lcrypto -ldl -lpthread -L../../target/debug/ -z noexecstack
	
compile:	
	PATH=/usr/lib/jvm/java-8-openjdk-amd64/bin:$PATH javac CroBindings.java Test.java

run:
	LD_LIBRARY_PATH=../../target/debug  java -Djava.library.path=.  Test
