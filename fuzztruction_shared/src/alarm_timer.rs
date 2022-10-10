use std::time::Duration;

use libc::syscall;

fn getitimer(which: libc::c_int, curr_value: &mut libc::itimerval) -> i64 {
    unsafe {
        syscall(
            libc::SYS_getitimer,
            which,
            curr_value as *const libc::itimerval,
        )
    }
}

fn setitimer(
    which: libc::c_int,
    new_value: &libc::itimerval,
    old_value: Option<&libc::itimerval>,
) -> i64 {
    let old_value = match old_value {
        Some(v) => v,
        None => std::ptr::null(),
    };

    unsafe {
        syscall(
            libc::SYS_setitimer,
            which,
            new_value as *const libc::itimerval,
            old_value as *const libc::itimerval,
        )
    }
}

pub struct AlarmTimer {
    value: libc::itimerval,
    handle_id: Option<signal_hook::SigId>,
}

impl AlarmTimer {
    pub fn new() -> Self {
        let value: libc::itimerval = unsafe { std::mem::zeroed() };
        AlarmTimer {
            value,
            handle_id: None,
        }
    }

    pub fn register_alarm_handler<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn() + Sync + Send + 'static,
    {
        unsafe {
            let ret = signal_hook::low_level::register(signal_hook::consts::SIGALRM, f).unwrap();
            self.handle_id = Some(ret);
        }
        self
    }

    pub fn unregister_alarm_handler(&mut self) -> &mut Self {
        signal_hook::low_level::unregister(
            self.handle_id
                .expect("Unregister called without a previous register call"),
        );
        self
    }

    pub fn schedule_alarm_in(&mut self, duration: Duration) {
        let ret = getitimer(libc::ITIMER_REAL, &mut self.value);
        assert!(ret == 0);

        let micro_secs = duration.as_micros();
        let seconds = (micro_secs / (1000 * 1000)) as i64;
        let micro_secs = (micro_secs % (1000 * 1000)) as i64;

        self.value.it_value.tv_sec += seconds;
        self.value.it_value.tv_usec += micro_secs;
    }

    pub fn disarm(&mut self) {
        self.value.it_value.tv_sec = 0;
        self.value.it_value.tv_usec = 0;
        let ret = setitimer(libc::ITIMER_REAL, &self.value, None);
        assert!(ret == 0);
    }
}

impl Drop for AlarmTimer {
    fn drop(&mut self) {
        self.disarm();
    }
}
