use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages
    if let Some(segment) = find_segment_containing(address) {
        // Step 4: Check if the access is valid.
        if !is_access_valid(segment, address) {
            eprintln!("Unauthorized access attempt at address {:x}", address);
            std::process::exit(-200);
        }
        unsafe {
            let page_start = address & !(0xFFF);
            let result = nix::sys::mman::mmap(
                page_start as *mut c_void,
                segment.size as usize, 
                segment.flags,        
                nix::sys::mman::MapFlags::MAP_FIXED | nix::sys::mman::MapFlags::MAP_PRIVATE,
                segment.fd,        
                segment.offset as libc::off_t, 
            );

            if result.is_err() {
                eprintln!("Failed to map memory at address {:x}", address);
                std::process::exit(-200);
            }
        }
    } else {
        eprintln!("Invalid memory access at address {:x}", address);
        std::process::exit(-200);
    }

}
fn find_segment_containing(address: usize) -> Option<&Segment> {
    unimplemented!();
}

fn is_access_valid(segment: &Segment, address: usize) -> bool {
    unimplemented!();
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
