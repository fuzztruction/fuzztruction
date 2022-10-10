extern crate proc_maps;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let pid = if args.len() > 1 {
        args[1].parse().expect("invalid pid")
    } else {
        panic!("Usage: print_maps PID");
    };

    let maps = proc_maps::get_process_maps(pid).expect("failed to get proc maps");
    for map in maps {
        println!(
            "Filename {:?} Address {} Size {}",
            map.filename(),
            map.start(),
            map.size()
        );
    }
}
