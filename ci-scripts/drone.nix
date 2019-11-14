with import <nixpkgs> {};

stdenv.mkDerivation {
    name = "dependencies";
    buildInputs = [
        bash
        git
        cmake
        openssl
        zeromq
        jq
        rustc
        cargo
        nodejs
    ];
    shellHook = ''
        export RUST_BACKTRACE=1
        export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
        export PATH="$PWD/node_modules/.bin/:$PATH"
        export OPENSSL_DIR="${openssl.dev}"
        export OPENSSL_LIB_DIR="${openssl.out}/lib"
        export LIBZMQ_PREFIX="/nix/store/$(ls /nix/store | grep -E "zeromq-[0-9\.]+$" | head -n1)/lib"
    '';
}