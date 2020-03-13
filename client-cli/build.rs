use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    let mut flags = ConstantsFlags::empty();
    flags.toggle(ConstantsFlags::BUILD_DATE);
    flags.toggle(ConstantsFlags::SHA_SHORT);

    generate_cargo_keys(flags).expect("Unable to generate the cargo keys!");
}
