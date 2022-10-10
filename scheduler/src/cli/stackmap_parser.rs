use std::path::Path;

use scheduler::llvm_stackmap::StackMap;

pub fn dump_stackmap(path: &Path) {
    println!("File: {:#?}", &path);
    log::info!("Start parsing");
    let stack_maps = StackMap::from_path(path).unwrap();
    log::info!("Parsing finished");
    for stack_map in stack_maps {
        stack_map.pretty_print();
    }
}
