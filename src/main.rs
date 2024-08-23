use nix::libc::siginfo_t;
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::SysconfVar::PAGE_SIZE;
use nix::unistd::{sysconf};
use std::error::Error;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_void};
use std::path::Path;

mod runner;

static mut PAGE_SIZE: usize = 0;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    let page_size = unsafe { PAGE_SIZE };
    let faulting_page = address & !(page_size - 1);

    if is_invalid_access(address) {
        println!("Segmentation fault at 0x{:x} page 0x{:x} (invalid)", address, faulting_page);
        std::process::exit(-200);
    } else {
        println!("Segmentation fault at 0x{:x} page 0x{:x} (access)", address, faulting_page);
        unsafe {
            if mmap(address as *mut c_void, page_size, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED, -1, 0).is_err() {
                println!("Failed to map page at 0x{:x}", address);
                std::process::exit(-200);
            }
            mprotect(address as *mut c_void, page_size, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE).unwrap_or_else(|_| {
                println!("Failed to protect page at 0x{:x}", address);
                std::process::exit(-200);
            });
        }
    }
}

fn is_invalid_access(address: usize) -> bool {
    // Define the range for valid addresses (can be adjusted based on requirements)
    address < 0x08048000 || address > 0xC0000000
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // Open the ELF file
    let file = fs::File::open(filename)?;
    let fd = file.as_raw_fd();
    let mut data = Vec::new();
    file.take(u64::MAX).read_to_end(&mut data)?;

    // Read ELF header and program headers
    let elf = object::File::parse(&data)?;
    let program_headers = elf.program_headers();
    let mut base_address = usize::MAX;
    let mut allocated_memory_ptrs = Vec::new();

    // Map the ELF segments
    for segment in program_headers {
        if segment.p_type() == object::elf::PT_LOAD {
            let p_vaddr = segment.p_vaddr() as usize;
            let p_memsz = segment.p_memsz() as usize;
            let p_filesz = segment.p_filesz() as usize;
            let p_flags = segment.p_flags();

            let actual_addr = p_vaddr & !(PAGE_SIZE - 1);
            let segment_size = p_memsz.max(p_filesz);

            unsafe {
                let ptr = mmap(
                    actual_addr as *mut c_void,
                    segment_size,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                    -1,
                    0
                )?;
                allocated_memory_ptrs.push(ptr);

                // Read segment data
                file.seek(SeekFrom::Start(segment.p_offset() as u64))?;
                let mut segment_data = vec![0; p_filesz];
                file.read_exact(&mut segment_data)?;
                std::ptr::copy_nonoverlapping(segment_data.as_ptr(), ptr as *mut u8, p_filesz);

                // Set segment protection
                mprotect(ptr, segment_size, ProtFlags::from_bits_truncate(p_flags as _))?;
            }

            if p_vaddr < base_address {
                base_address = p_vaddr;
            }
        }
    }

    // Entry point
    let entry_point = elf.entry() as usize;

    // Register SIGSEGV handler
    let handler = SigHandler::SigAction(sigsegv_handler);
    let action = SigAction::new(handler, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &action) }?;

    // Run the ELF file
    runner::exec_run(base_address, entry_point);

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        PAGE_SIZE = sysconf(PAGE_SIZE)?.unwrap_or(4096);
    }
    // Load ELF file from command-line argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <executable>", args[0]);
        std::process::exit(1);
    }
    let filename = &args[1];
    exec(filename)
}
