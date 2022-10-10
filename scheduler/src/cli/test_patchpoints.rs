use fuzztruction_shared::constants::PATCH_POINT_SIZE;
use hex::ToHex;
use scheduler::{
    config::Config,
    fuzzer::queue::Input,
    mutation_cache::{MutationCache, MutationCacheEntryFlags},
    mutation_cache_ops::MutationCacheOpsEx,
    source::{self, Source},
};

pub fn run(config: &Config, with_mutations: bool) {
    // Take the first seed file for testing.
    let inputs = Input::from_dir(&config.general.input_dir).unwrap();
    let first_input = inputs
        .get(0)
        .expect("Seed directory must contain at least one file.");
    let first_input_bytes = first_input.data();

    let mut source_output = Vec::new();
    let mut source = Source::from_config(config, None).unwrap();
    source.start().unwrap();

    let patch_points = source.get_patchpoints().unwrap();
    log::info!("#Patch Points with libraries : {}", patch_points.len());

    let mc = MutationCache::from_patchpoints(patch_points.iter()).unwrap();
    source.mutation_cache_replace(&mc).unwrap();

    source.write(first_input_bytes);
    let run_res = source.run(config.general.timeout).unwrap();
    log::info!("RunResult with all patchpoints disabled: {:?}", run_res);

    log::info!(
        "Tracing target. Timeout is set to {:?}",
        config.general.tracing_timeout
    );
    source.write(first_input_bytes);
    let trace_result = source.trace(config.general.tracing_timeout).unwrap();
    source.read(&mut source_output);
    log::info!("Trace run result: {:?}", trace_result.0);
    log::info!("Trace length: {:?}", trace_result.1.len());

    log::info!("Performing second traceing run to test stability.");
    source.write(first_input_bytes);
    let trace_result_test = source.trace(config.general.tracing_timeout).unwrap();
    source.read(&mut source_output);
    assert_eq!(trace_result_test.1.len(), trace_result.1.len());

    if source_output.is_empty() {
        log::error!("Source did not produce any output during tracing!");
        source.stop().unwrap();
        return;
    }

    let trace = &trace_result.1;
    source.mutation_cache_apply_fn_mut(|m| {
        unsafe {
            m.remove_uncovered(trace);
        }
        m.reset_flags();
        m.set_flag(MutationCacheEntryFlags::Disable);
    });

    if with_mutations {
        log::info!("Applying empty mutations masks to all covered patch points.");
        source.mutation_cache_apply_fn_mut(|m| unsafe {
            m.resize_covered_entries(trace);
        });
    }

    let mc = source.mutation_cache();
    let mut mc_borrow = mc.borrow_mut();
    let mc_len = mc_borrow.len();
    assert_eq!(mc_len, trace_result.1.len());

    let mut entries = mc_borrow.entries_mut();
    entries.sort_by_key(|e| e.vma());

    let mut covered_cnt = 0;
    let mut idx = 0;
    for entry in entries {
        idx += 1;

        entry.reset_flags();
        entry.enable_tracing();
        entry.enable();
        log::info!("Testing entry {} of {}", idx, mc_len);
        log::info!("entry={:#?} @ vma=0x{:x}", entry, entry.vma());

        if config.general.jail_enabled() {
            // acquire privileges, thus we are able to read the targets process memory.
            jail::acquire_privileges().unwrap();
        }

        let mem_old = source
            .read_mem(entry.vma() as usize, PATCH_POINT_SIZE)
            .unwrap();
        let mem_old: String = mem_old.encode_hex();

        source.sync_mutations().unwrap();
        let new_mem = source
            .read_mem(entry.vma() as usize, PATCH_POINT_SIZE)
            .unwrap();
        let new_mem: String = new_mem.encode_hex();

        let uid_gid = config.general.jail_uid_gid();
        if let Some((uid, gid)) = uid_gid {
            jail::drop_privileges(uid, gid, false).unwrap();
        }

        source.write(first_input_bytes);
        let run_res = source.run(config.general.tracing_timeout).unwrap();
        source.read(&mut source_output);

        match run_res {
            source::RunResult::Signalled { signal, .. } => {
                let pp = patch_points.iter().find(|e| e.id() == entry.id()).unwrap();
                log::error!("memory @ patchpoint before patching : {:?}", mem_old);
                log::error!("memory @ patchpoint after patching  : {:?}", new_mem);
                log::error!("Signalled ({:?}) after tracing entry {:#?} that belongs to the following patch point {:#?}", signal, entry, pp);
                break;
            }
            source::RunResult::TimedOut { .. } => {
                log::error!("Timeout after tracing entry {:#?}", entry);
                break;
            }
            source::RunResult::Terminated { msgs, .. } => {
                log::info!("memory @ patchpoint before patching : {:?}", mem_old);
                log::info!("memory @ patchpoint after patching  : {:?}", new_mem);
                if msgs.len() != 1 {
                    log::error!("Unexpected number of messages received: {:#?}", msgs);
                    //break;
                } else {
                    covered_cnt += 1;
                }
            }
        }

        if source_output.is_empty() {
            log::error!("Source did not produce any output!");
            break;
        }

        entry.reset_flags();
        entry.disable();
    }

    log::info!("Covered {} entries out of {}", covered_cnt, mc_len);
    if covered_cnt == 0 {
        log::error!("This looks odd! No entry was covered during testing each entry seperately.")
    }

    source.stop().unwrap();
}
