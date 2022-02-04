mod deferred;
mod injector;

use deferred::Deferred;
pub use injector::{Error, Result};

pub fn inject_dll_manual_map(pid: u32, filename: &str) -> Result<()> {
    unsafe {
        let mut deferred = Deferred::new();
        let h_process = injector::open_process(&mut deferred, pid)?;

        injector::inject_dll_manual_map(&mut deferred, h_process, filename)
    }
}

pub fn inject_dll_load_library(pid: u32, filename: &str) -> Result<()> {
    unsafe {
        let mut deferred = Deferred::new();
        let h_process = injector::open_process(&mut deferred, pid)?;

        injector::inject_dll_load_library(&mut deferred, h_process, filename)
    }
}
