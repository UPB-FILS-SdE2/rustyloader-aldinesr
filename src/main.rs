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
   
    // determine base address

    // determine entry point

    // register SIGSEGV handler

    // run ELF using runner::exec_run

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // load ELF provided within the first argument
    let mut file = fs::File::open(filename)?;
    let fd = file.as_raw_fd();
    let data = fs::read(filename)?;
    let elf = elf::FileHeader32::<object::Endianness>::parse(&*data)?;
    let endian = elf.endian()?;

    let entry_point = elf.e_entry.get(object::Endianness::Little) as usize;
    let program_headers = elf.program_headers(endian, &data)?;

    let mut load_segments: Vec<ProgramHeader32<Endianness>> = vec![];
    for segment in program_headers {
        if segment.p_type.get(object::Endianness::Little) == 1 {
            load_segments.push(segment.clone());
        }
    }

    let mut allocated_memory_ptrs: Vec<*mut c_void> = vec![];
    let mut base_address: usize = usize::MAX;

    eprintln!("Segments");
    eprintln!("# address size offset length flags");
    let mut i = 0;
    for load_segment in load_segments {
        let p_offset = load_segment.p_offset(object::Endianness::Little) as usize;
        let p_vaddr = load_segment.p_vaddr(object::Endianness::Little) as usize;
        let p_memsz = load_segment.p_memsz(object::Endianness::Little) as usize;
        let p_flags = load_segment.p_flags(object::Endianness::Little) as usize;
        let p_filesz = load_segment.p_filesz(object::Endianness::Little) as usize;

        let actual_addr = p_vaddr - (p_vaddr % PAGE_SIZE);
        let actual_offset = p_offset - (p_offset % PAGE_SIZE);

        let segment_perms = SegmentPerms::from_number(p_flags);

        eprintln!(
            "{} 0x{:x} {} 0x{:x} {} {}",
            i,
            p_vaddr,
            p_memsz,
            p_offset,
            p_filesz,
            segment_perms.to_string()
        );
        i += 1;

        let p = unsafe {
            mmap(
                actual_addr as *mut c_void,
                p_memsz,
                ProtFlags::PROT_WRITE | ProtFlags::PROT_READ | segment_perms.to_flags(),
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
        };

        if let Err(e) = p {
            println!("{}", e);
            std::process::exit(-1);
        }
        let p = p.unwrap();

        file.seek(SeekFrom::Start(actual_offset as u64))?;
        let mut segment = vec![0; p_filesz];
        file.read_exact(&mut segment)?;

        unsafe {
            std::ptr::copy_nonoverlapping(segment.as_ptr(), p as *mut u8, p_filesz);
            mprotect(p, p_memsz, segment_perms.to_flags())?;
        }

        if p_vaddr < base_address {
            base_address = p_vaddr;
        }

        allocated_memory_ptrs.push(p);
    }

    eprintln!("Entry point {:x}", entry_point);
    eprintln!("Base address {:x}", base_address);

    let handler = SigHandler::SigAction(sigsegv_handler);
    let action = SigAction::new(handler, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &action) }?;

    Ok(runner::exec_run(base_address, entry_point))
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        PAGE_SIZE = sysconf(SysconfVar::PAGE_SIZE)
            .unwrap_or_else(|_| panic!("can't set global PAGE_SIZE"))
            .unwrap_or_else(|| panic!("can't set global PAGE_SIZE --- 2"));
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <executable>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    exec(filename).unwrap_or_else(|_| panic!("can't execute file"));
    Ok(())
}