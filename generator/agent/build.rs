use std::{path::PathBuf, process};

fn main() {
    println!("Building source llvm pass...");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut cmd = process::Command::new("make");
    let cwd = PathBuf::from(manifest_dir).join("../pass");
    cmd.current_dir(cwd);
    cmd.spawn().unwrap();
}
