use std::{
    env,
    path::PathBuf,
    time::{Duration, Instant},
};

use scheduler::sink::AflSink;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[!] No path specified");
        return;
    }

    let path = PathBuf::from(args[1].clone());
    let mut sink = AflSink::new(
        path,
        args[2..].to_vec(),
        PathBuf::from("/tmp"),
        scheduler::io_channels::InputChannel::Stdin,
        None,
        true,
        true,
    )
    .unwrap();
    sink.start().expect("Failed to start sink!");

    let start = Instant::now();
    const TIMEOUT: Duration = Duration::from_millis(1000);
    const ITERATIONS: usize = 20_000;
    for _ in 0..ITERATIONS {
        let _res = sink.run(TIMEOUT).unwrap();
    }

    println!(
        "{} execs/s",
        ITERATIONS as f64 / (start.elapsed().as_secs_f64())
    );
}
