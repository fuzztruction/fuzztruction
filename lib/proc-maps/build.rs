#[cfg(all(feature = "generate-bindings", target_os = "freebsd"))]
extern crate bindgen;

fn main() {
    #[cfg(all(feature = "generate-bindings", target_os = "freebsd"))]
    {
        println!("cargo:rerun-if-changed=src/freebsd_maps/wrapper.h");

        let bindings = bindgen::Builder::default()
            .header("src/freebsd_maps/wrapper.h")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file("src/freebsd_maps/bindings.rs")
            .expect("Couldn't write bindings!");
    }
}
