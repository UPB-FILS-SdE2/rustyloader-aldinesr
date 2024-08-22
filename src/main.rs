use nix::libc::siginfo_t;
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::{getpid, sysconf, SysconfVar};
use std::error::Error;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_void};
use std::path::Path;

use object::read::elf::{FileHeader, ProgramHeader32};
use object::{elf, Endianness, Object};
use perms::SegmentPerms;
use runner;

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages
    if address < 0x08048000 || address > 0xC0000000 {
        println!(
            "Segmentation fault at 0x{:x} page 0x{:x} (invalid)",
            address,
            address & !(PAGE_SIZE - 1)
        );
        std::process::exit(56);
    } else {
        unsafe {
            let code = (*siginfo).si_code;
            if code == 1 {
                println!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (invalid)",
                    address,
                    address & !(PAGE_SIZE - 1)
                );
            } else if code == 2 {
                println!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (access)",
                    address,
                    address & !(PAGE_SIZE - 1)
                );
            } else {
                println!("Unknown SEGV code: {}", code);
            }
            mmap(
                address as *mut c_void,
                PAGE_SIZE,
                ProtFlags::all(),
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
            .unwrap_or_else(|_| {
                println!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (access)",
                    address,
                    address & !(PAGE_SIZE - 1)
                );
                std::process::exit(56);
            });
        }
    }

}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // read ELF segments 
  

    // print segments
    let mut segments = vec![];
    for segment in elf.segments() {
        let address = segment.address();
        let size = segment.size();
        let offset = segment.file_range().0;
        let length = segment.file_range().1;
        let flags = segment.flags();
        println!("#\taddress\t\tsize\toffset\tlength\tflags");
        println!(
            "{}\t{:#x}\t{}\t{:#x}\t{}\t{}",
            segments.len(),
            address,
            size,
            offset,
            length,
            format_flags(flags)
        );
        segments.push(segment);
    }
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
