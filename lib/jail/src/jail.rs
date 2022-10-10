use anyhow::{anyhow, Context, Result};
use libc;
use std::{
    collections::HashSet,
    env,
    ffi::OsStr,
    fs, io,
    os::unix,
    path::{Path, PathBuf},
    process,
};
use tempfile;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JailError {
    #[error("OsError: {0}")]
    OsError(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct Jail {
    builder: JailBuilder,
    new_root: String,
}

pub fn wrap_libc<T>(function: T) -> Result<i32>
where
    T: Fn() -> i32,
{
    let ret = function();
    if ret != 0 {
        let err = io::Error::last_os_error();
        Err(err)
            .context("Error during execution of libc function!")
            .context(format!("ret={}", ret))
    } else {
        Ok(ret)
    }
}

pub fn drop_privileges(uid: u32, gid: u32, permanent: bool) -> Result<()> {
    if permanent {
        unsafe {
            wrap_libc(|| libc::setgid(gid))?;
            wrap_libc(|| libc::setuid(uid))?;
        }
    } else {
        unsafe {
            wrap_libc(|| libc::setegid(gid))?;
            wrap_libc(|| libc::seteuid(uid))?;
        }
    }

    Ok(())
}

pub fn acquire_privileges() -> Result<()> {
    unsafe {
        wrap_libc(|| libc::seteuid(0)).context("Failed to call seteuid(0)")?;
        wrap_libc(|| libc::setegid(0)).context("Failed to call setegid(0)")?;
    };
    Ok(())
}

impl Jail {
    fn from_builder(builder: JailBuilder) -> Result<Jail> {
        let new_root = tempfile::Builder::new()
            .prefix("ft_jail_")
            .tempdir_in("/tmp")
            .context("Failed to create new root directory in /tmp")?;
        let new_root = new_root.into_path();
        let new_root_str = new_root.to_str().context("Failed to convert Path to str")?;

        let ret = Jail {
            builder,
            new_root: new_root_str.to_owned(),
        };
        Ok(ret)
    }

    fn acquire_privileges(&self) -> Result<()> {
        acquire_privileges()?;
        Ok(())
    }

    fn drop_privileges(&self, permanent: bool) -> Result<()> {
        if let Some(target_ids) = self.builder.drop_to {
            drop_privileges(target_ids.0, target_ids.1, permanent)?
        }
        Ok(())
    }

    fn _with_dropped_privileges<T>(&self, f: impl Fn() -> T) -> Result<T> {
        self.drop_privileges(false)?;
        let ret = f();
        self.acquire_privileges()?;
        Ok(ret)
    }

    fn mount(args: &[impl AsRef<OsStr>]) -> Result<process::Output> {
        let mut process = process::Command::new("mount");
        process.args(args);
        let ret = process.output().context("Failed to get process output")?;
        if !ret.status.success() {
            return Err(anyhow!("mount termiated with an error code: {:#?}", ret));
        }
        Ok(ret)
    }

    fn _umount(args: &[impl AsRef<OsStr>]) -> Result<process::Output> {
        let mut process = process::Command::new("umount");
        process.args(args);
        let ret = process.output().context("Failed to get process output")?;
        if !ret.status.success() {
            return Err(anyhow!("mount termiated with an error code: {:#?}", ret));
        }
        Ok(ret)
    }

    /// Enter the Jail. This will cause the calling process to be moved into the
    /// Jail. Calling this function requires the calling process to have EUID of 0.
    pub fn enter(&mut self) -> Result<()> {
        self.acquire_privileges()
            .context("Failed to acquire privileges")?;

        // Make sure mounts to /tmp are visible in this mount NS and the unshared
        // one.
        //Jail::mount(&["--make-shared", "/tmp"]).context("Failed to make /tmp shared")?;

        // Unshare the mount namescpace
        let ret = unsafe { libc::unshare(libc::CLONE_NEWNS) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to unshare mount namespace");
        }

        // Create the directory we are going to perpare our new root tree.
        println!("Root is at {:?}", self.new_root);

        // Mount the bear minimum to allow execution of software.

        // Mount / as RO. This does not contain any submounts!
        Jail::mount(&["-o", "rbind,ro", "/", &self.new_root])
            .context("Failed to mount / into new root")?;

        // Mount /proc, /sys and /dev. These are shared since they are also marked as shared in the "parent" namespace.
        Jail::mount(&["-o", "bind", "/proc", &format!("{}/proc", self.new_root)])
            .context("Failed to mount /proc")?;
        Jail::mount(&["-o", "bind", "/sys", &format!("{}/sys", self.new_root)])
            .context("Failed to mount /sys")?;
        Jail::mount(&["-o", "rbind", "/dev", &format!("{}/dev", self.new_root)])
            .context("Failed to mount /dev")?;

        if self.builder.no_random_devices {
            // Mount /dev/zero in place of the listed devices.
            for dst in ["hwrng", "random", "urandom"] {
                Jail::mount(&["-o", "bind", "/dev/zero", &format!("/dev/{}", dst)])
                    .context(format!("Failed to mount /dev/zero to {}", dst))?;
            }
        }

        // mount tmpfs at /tmp
        Jail::mount(&[
            "-t",
            "tmpfs",
            "-o",
            "noatime",
            "none",
            &format!("{}/tmp", self.new_root),
        ])
        .context("Failed mount tmpfs to /tmp in new root")?;

        // Mount all RW dirs
        for path in self.builder.rw_binds.iter() {
            println!("Mounting directory {:?} as RW", path);
            if !path.exists() {
                return Err(anyhow!("Trying to make non existing path rw: {:?}", path));
            }
            let path = path.to_str().unwrap();
            let dst_path = format!("{}/{}", self.new_root, path);
            self.drop_privileges(false)?;
            fs::create_dir_all(&dst_path)
                .context(format!("Failed to crate mount dst dir: {:?}", &dst_path))?;
            self.acquire_privileges()?;
            Jail::mount(&["--bind", "-o", "rw", path, &dst_path])
                .context(format!("Failed to mount {} to {}", path, &dst_path))?;
        }

        // Mount all RO dirs
        for path in self.builder.ro_binds.iter() {
            println!("Mounting directory {:?} as RO", path);
            if !path.exists() {
                return Err(anyhow!("Trying to make non existing path rw: {:?}", path));
            }
            let path = path.to_str().unwrap();
            let dst_path = format!("{}/{}", self.new_root, path);
            self.drop_privileges(false)?;
            fs::create_dir_all(&dst_path)
                .context(format!("Failed to crate mount dst dir: {:?}", &dst_path))?;
            self.acquire_privileges()?;
            Jail::mount(&["--bind", "-o", "ro", path, &dst_path])
                .context(format!("Failed to mount {} to {}", path, &dst_path))?;
        }

        println!("Switching to new root");
        unix::fs::chroot(&self.new_root)?;
        env::set_current_dir("/").context("Failed to switch working directory")?;
        self.drop_privileges(true)?;

        let out = process::Command::new("cat")
            .args(["/proc/self/mountinfo"])
            .output();
        println!("{}", String::from_utf8(out.unwrap().stdout).unwrap());

        Ok(())
    }

    /// Resolve a path from the mount namespace the jail was initially build in.
    pub fn resolve_path_from_child(&self, path: &impl AsRef<Path>) -> PathBuf {
        let path_ref = path.as_ref();
        match path_ref.strip_prefix(&self.new_root) {
            Ok(path) => {
                let p = path.to_owned();
                let mut prefix = PathBuf::new();
                // strippings produces a path that has no leading slash,
                // thus we need to readd one.
                prefix.push("/");
                prefix.push(p);
                prefix
            }
            Err(..) => {
                // `new_root` is no prefix
                path_ref.to_owned()
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct JailBuilder {
    rw_binds: HashSet<PathBuf>,
    ro_binds: HashSet<PathBuf>,
    drop_to: Option<(u32, u32)>,
    no_random_devices: bool,
}

impl JailBuilder {
    /// Create a new `JailBuilder`.
    pub fn new() -> JailBuilder {
        JailBuilder {
            rw_binds: HashSet::new(),
            ro_binds: HashSet::new(),
            drop_to: None,
            no_random_devices: false,
        }
    }

    /// Build the `Jail` according to the `JailBuilder`.
    /// If this method is directly called without altering the builder
    /// via its methods, the resulting Jail will have the following properties:
    ///     - The process calling `enter()` on the `Jail` will be moved into a new
    ///       mount namespace.
    ///     - "/"" of the calling processes namespace is mounted readonly as the new
    ///       root into the new mount namespace
    ///     - In the new mount namespace:
    ///         - /tmp is mounted as tmpfs without limited size
    ///         - /proc /sys is bind mounted from the parent namespace.
    ///         - /dev and its children (e.g., /dev/shm, /dev/mqueue) are bind
    ///           mounted from the parent namespace.
    pub fn build(self) -> Result<Jail> {
        // Check if ro / rw binds are not prefixes of each other.
        Jail::from_builder(self)
    }

    /// Mount the given `path` read and writeable inside the `Jail`.
    pub fn bind_rw(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.rw_binds.insert(path.as_ref().to_owned());
        self
    }

    /// Mount the given `path` readonly inside the `Jail`.
    pub fn bind_ro(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.ro_binds.insert(path.as_ref().to_owned());
        self
    }

    /// Drop the privileges after entering the `Jail`.
    pub fn drop_privileges(&mut self, user: u32, group: u32) -> &mut Self {
        self.drop_to = Some((user, group));
        self
    }

    /// Replace random devices like random, urandom, ... with /dev/zero inside
    /// the jails mount namespace.
    pub fn no_random_devices(&mut self) -> &mut Self {
        self.no_random_devices = true;
        self
    }
}
