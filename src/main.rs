use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};
use object::{Object, ObjectSegment, elf::ElfFile};
use nix::libc::{signal, SIGSEGV, sigaction, SA_SIGINFO, sigemptyset, sigaction as SigAction, siginfo_t, sighandler_t};
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::mem;

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages
    if let Some(segment) = find_segment_containing(address) {
        if !is_access_valid(segment, address) {
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
                std::process::exit(-200);
            }
        }
    } else {
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
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let elf = ElfFile::parse(&buffer)?;

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
