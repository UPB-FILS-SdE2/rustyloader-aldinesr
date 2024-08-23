use nix::libc::siginfo_t;
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::SysconfVar::PAGE_SIZE;
use nix::unistd::sysconf;
use std::error::Error;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_void};
use std::path::Path;
use object::elf::ProgramHeader32;
use object::read::elf::FileHeader;
use object::{elf, Endianness, Object};

mod perms;
mod runner;

static mut PAGE_SIZE: usize = 0;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    let page_size = unsafe { PAGE_SIZE };

    if address < 0x08048000 || address > 0xC0000000 {
        std::process::exit(56);
    } else {
        unsafe {
            let code = (*siginfo).si_code;
            if code == 1 || code == 2 {
                std::process::exit(56);
            } else {
                std::process::exit(56);
            }
        }
    }

    unsafe {
        mmap(
            address as *mut c_void,
            page_size,
            ProtFlags::all(),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
            -1,
            0,
        ).unwrap_or_else(|_| {
            std::process::exit(56);
        });
    }
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    let file = fs::File::open(filename)?;
    let fd = file.as_raw_fd();
    let data = fs::read(filename)?;
    let elf = elf::FileHeader32::<object::Endianness>::parse(&*data)?;
    let endian = elf.endian()?;
    let entry_point = elf.e_entry.get(object::Endianness::Little) as usize;
    let program_headers = elf.program_headers(endian, data.as_slice())?;

    let mut load_segments = Vec::new();
    for segment in program_headers {
        if segment.p_type.get(object::Endianness::Little) == 1 { // is LOAD
            load_segments.push(segment);
        }
    }

    let mut allocated_memory_ptrs = Vec::new();
    let mut base_address = usize::MAX;

    for (i, load_segment) in load_segments.iter().enumerate() {
        let p_offset = load_segment.p_offset(object::Endianness::Little) as usize;
        let p_vaddr = load_segment.p_vaddr(object::Endianness::Little) as usize;
        let p_memsz = load_segment.p_memsz(object::Endianness::Little) as usize;
        let p_flags = load_segment.p_flags(object::Endianness::Little) as usize;
        let p_filesz = load_segment.p_filesz(object::Endianness::Little) as usize;

        let actual_addr = p_vaddr - (p_vaddr % unsafe { PAGE_SIZE });
        let segment_size = p_memsz;
        
        let segment_perms = perms::SegmentPerms::from_number(p_flags);

        unsafe {
            let ptr = mmap(
                actual_addr as *mut c_void,
                segment_size,
                ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )?;

            allocated_memory_ptrs.push(ptr);

            file.seek(SeekFrom::Start(p_offset as u64))?;
            let mut segment_data = vec![0; p_filesz];
            file.read_exact(&mut segment_data)?;

            std::ptr::copy_nonoverlapping(segment_data.as_ptr(), ptr as *mut u8, p_filesz);
            mprotect(ptr, segment_size, segment_perms.to_flags())?;
        }

        if p_vaddr < base_address {
            base_address = p_vaddr;
        }
    }

    let handler = SigHandler::SigAction(sigsegv_handler);
    let action = SigAction::new(handler, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &action) }?;

    runner::exec_run(base_address, entry_point);

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        PAGE_SIZE = sysconf(PAGE_SIZE)?
            .unwrap_or(4096);
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <executable>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    exec(filename)?;

    Ok(())
}
