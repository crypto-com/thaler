extern crate bindgen;
fn main() {
    let bindings = bindgen::Builder::default()
        .header("./chain.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file("./src/bindings.rs")
        .expect("Couldn't write bindings!");
}
