use nix::libc::siginfo_t;
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
use nix::sys::signal::{sigaction, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::sysconf;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_void};
use std::path::Path;

use object::elf::*;
use object::read::{elf, Endianness, ProgramHeader32};
use object::Object;

static mut PAGE_SIZE: usize = 0;

extern "C" fn sigsegv_handler(signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;

    if address < 0x08048000 || address > 0xC0000000 {
        eprintln!(
            "Segmentation fault at 0x{:x} page 0x{:x} (invalid)",
            address,
            address & !(PAGE_SIZE - 1)
        );
        std::process::exit(56);
    } else {
        unsafe {
            let code = (*siginfo).si_code;
            if code == 1 || code == 2 {
                eprintln!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (access)",
                    address,
                    address & !(PAGE_SIZE - 1)
                );
                std::process::exit(56);
            } else {
                eprintln!("Unknown SEGV code: {}", code);
            }

            mmap(
                address as *mut c_void,
                PAGE_SIZE,
                ProtFlags::all(),
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
            .unwrap_or_else(|e| {
                eprintln!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (access)",
                    address,
                    address & !(PAGE_SIZE - 1)
                );
                std::process::exit(56);
            });
        }
    }
}

fn display_segments(segments: &[ProgramHeader32<Endianness>]) {
    eprintln!("Segments");
    eprintln!("#\taddress\tsize\toffset\tlength\tflags");
    for (i, segment) in segments.iter().enumerate() {
        let p_vaddr = segment.p_vaddr(object::Endianness::Little) as usize;
        let p_memsz = segment.p_memsz(object::Endianness::Little) as usize;
        let p_offset = segment.p_offset(object::Endianness::Little) as usize;
        let p_filesz = segment.p_filesz(object::Endianness::Little) as usize;
        let p_flags = segment.p_flags(object::Endianness::Little) as usize;

        let perms = SegmentPerms::from_number(p_flags);

        eprintln!(
            "{}\t0x{:08x}\t{}\t0x{:x}\t{}\t{}",
            i, p_vaddr, p_memsz, p_offset, p_filesz, perms
        );
    }
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let fd = file.as_raw_fd();
    let data = std::fs::read(filename)?;
    let elf = elf::FileHeader32::<object::Endianness>::parse(&*data)?;
    let endian = elf.endian()?;

    let entry_point = elf.e_entry.get(object::Endianness::Little) as usize;
    let program_headers = elf.program_headers(endian, data.as_slice())?;
    let load_segments: Vec<_> = program_headers
        .iter()
        .filter(|seg| seg.p_type.get(object::Endianness::Little) == 1)
        .collect();

    let base_address = load_segments
        .iter()
        .map(|seg| seg.p_vaddr.get(object::Endianness::Little) as usize)
        .min()
        .unwrap_or(usize::MAX);

    display_segments(&load_segments);

    eprintln!("Entry point {:x}", entry_point);
    eprintln!("Base address {:x}", base_address);

    unsafe {
        PAGE_SIZE = sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
            .unwrap_or_else(|_| panic!("can't get page size"))
            .unwrap_or(4096);
    }

    let handler = SigHandler::SigAction(sigsegv_handler);
    let action = SigAction::new(handler, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &action) }.expect("Failed to set signal handler");

    // Load segments into memory
    for segment in load_segments {
        let p_offset = segment.p_offset(object::Endianness::Little) as usize;
        let p_vaddr = segment.p_vaddr(object::Endianness::Little) as usize;
        let p_memsz = segment.p_memsz(object::Endianness::Little) as usize;
        let p_filesz = segment.p_filesz(object::Endianness::Little) as usize;
        let p_flags = segment.p_flags(object::Endianness::Little) as usize;

        let actual_addr = p_vaddr - (p_vaddr % PAGE_SIZE);
        let actual_offset = p_offset - (p_offset % PAGE_SIZE);

        let segment_perms = SegmentPerms::from_number(p_flags);

        unsafe {
            mmap(
                actual_addr as *mut c_void,
                p_memsz,
                segment_perms.to_flags(),
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )?;
            file.seek(SeekFrom::Start(actual_offset as u64))?;
            let mut segment_data = vec![0; p_filesz];
            file.read_exact(&mut segment_data)?;
            std::ptr::copy_nonoverlapping(segment_data.as_ptr(), actual_addr as *mut u8, p_filesz);
        }
    }

    // Execute entry point
    let entry_func: extern "C" fn() = unsafe { std::mem::transmute(entry_point) };
    entry_func();

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    exec(&std::env::args().nth(1).ok_or("Usage: <executable>")?)
}
