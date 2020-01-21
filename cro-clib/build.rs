extern crate cbindgen;

fn main() {
    cbindgen::generate(".")
        .expect("Unable to generate bindings")
        .write_to_file("./chain.h");

    cbindgen::generate("../chain-core")
        .expect("Unable to generate bindings")
        .write_to_file("./chain-core.h");
}
