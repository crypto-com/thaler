with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "rust-env";
  nativeBuildInputs = [
    rustc cargo
  ];
  LIBCLANG_PATH="${llvmPackages.libclang}/lib";
  buildInputs = [
    # Example Run-time Additional Dependencies
    openssl zeromq rocksdb clang  gcc pkgconfig binutils-unwrapped gdb llvm	
  ];

 shellHook = ''
    export LD_LIBRARY_PATH="/nix/store/$(ls /nix/store | grep -E "zeromq-[0-9\.]+$" | head -n1)/lib":$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH="/nix/store/$(ls /nix/store | grep -E "clang-[0-9\.]+$" | head -n1)/lib":$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH="/nix/store/$(ls /nix/store | grep -E "libffi-[0-9\.]+$" | head -n1)/lib":$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH="/nix/store/$(ls /nix/store | grep -E "llvm_6.0" | head -n1)/lib":$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH="/nix/store/$(ls /nix/store | grep -E "gcc-6.5.0-lib" | head -n1)/lib":$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH="/nix/store/$(ls /nix/store | grep -E "libedit" | head -n1)/lib":$LD_LIBRARY_PATH
  '';

  # Set Environment Variables
  RUST_BACKTRACE = 1;
}
