use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // read ELF segments 

    // print segments

    // determine base address

    // determine entry point

    // register SIGSEGV handler

    // run ELF using runner::exec_run

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // load ELF provided within the first argument
    Ok(())
}
