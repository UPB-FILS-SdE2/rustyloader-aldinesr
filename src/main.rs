use nix::libc::siginfo_t;
use nix::sys::mman::{mmap, mprotect, munmap, MapFlags, ProtFlags};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::SysconfVar::PAGE_SIZE;
use nix::unistd::{getpid, sysconf};
use perms::SegmentPerms;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_void};
use std::path::Path;

use object::read::elf::{FileHeader, Sym};
use object::{elf, Endian, Endianness, LittleEndian, Object, ObjectSection, Section, Segment};
use std::error::Error;
use std::fs;

use object::elf::*;
use object::read::elf::*;
use object::read::{SectionIndex, StringTable, SymbolIndex};

mod perms;
mod runner;

static mut page_size: i32 = 0;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages

    // println!("Page fault at address: 0x{:x}", address);

    if address < 0x08048000 || address > 0xC0000000 {
        // println!("Segmentation fault at 0x8048100 page 0x8048000 (access)")
        println!(
            "Segmentation fault at 0x{:x} page 0x{:x} (invalid)",
            address,
            address & !(unsafe { page_size } as usize - 1)
        );
        std::process::exit(56);
    } else {
        unsafe {
            let code = (*siginfo).si_code;
            if code == 1 {
                // println!("SEGV_MAPERR");
                println!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (invalid)",
                    address,
                    address & !(unsafe { page_size } as usize - 1)
                );
                std::process::exit(56);
                //invalid
            } else if code == 2 {
                // println!("SEGV_ACCERR");
                println!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (access)",
                    address,
                    address & !(unsafe { page_size } as usize - 1)
                );
                std::process::exit(56);
                //access
            } else {
                println!("Unknown SEGV code: {}", code);
            }
        }
        // println!("0x{:x}", address);
        unsafe {
            mmap(
                address as *mut c_void,
                page_size as usize,
                ProtFlags::all(),
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
            .unwrap_or_else(|e| {
                // panic!("{}", format!("{:#?}", e))
                // println!("{:#?}", e);
                println!(
                    "Segmentation fault at 0x{:x} page 0x{:x} (access)",
                    address,
                    address & !(page_size as usize - 1)
                );

                std::process::exit(56);
            });
        }
    }

    // unsafe {
    //   mmap(address as *mut c_void,
    //     page_size as usize,
    //     ProtFlags::PROT_NONE,
    //     MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
    //     -1,
    //     0);
    // }

    // std::process::exit(0);
}

fn segment_to_string(segment: &ProgramHeader32<Endianness>) -> String {
    format!(
        "ProgramHeader32 {}
  p_type: 0x{:x},
  p_offset: 0x{:x},
  p_vaddr: 0x{:x},
  p_paddr: 0x{:x},
  p_filesz: 0x{:x},
  p_memsz: 0x{:x},
  p_flags: 0x{:x},
  p_align: 0x{:x},
{}",
        "{",
        segment.p_type.get(object::Endianness::Little),
        segment.p_offset.get(object::Endianness::Little),
        segment.p_vaddr.get(object::Endianness::Little),
        segment.p_paddr.get(object::Endianness::Little),
        segment.p_filesz.get(object::Endianness::Little),
        segment.p_memsz.get(object::Endianness::Little),
        segment.p_flags.get(object::Endianness::Little),
        segment.p_align.get(object::Endianness::Little),
        "}"
    )
}

struct NerosSection {
    name: String,
    address: u64,
    size: u64,
    align: u64,
}

// impl core::fmt::Display for NerosSection {
//   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//       write!(f, "NerosSection {{\n\tname: \"{}\"\n\taddress: 0x{:x}\n\tsize: 0x{:x}\n\talign: 0x{:x}\n}}", self.name, self.address, self.size, self.align)
//   }
// }

impl core::fmt::Debug for NerosSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NerosSection")
            .field("name", &self.name)
            .field("address", &format_args!("0x{:X}", self.address))
            .field("size", &format_args!("0x{:X}", self.size))
            .field("align", &format_args!("0x{:X}", self.align))
            .finish()
    }
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    let mut file = fs::File::open(filename)?;
    let fd = file.as_raw_fd();
    let data = fs::read(filename)?;
    let elf = elf::FileHeader32::<object::Endianness>::parse(&*data)?;
    let endian = elf.endian()?;

    let virtual_address_entry = elf.e_entry;

    let entry_point = virtual_address_entry.get(object::Endianness::Little) as usize;
    let program_headers = elf
        .program_headers(endian, data.as_slice())
        .unwrap_or_else(|_| panic!("can't read program's headers"));

    let mut load_segments: Vec<ProgramHeader32<Endianness>> = vec![];

    for segment in program_headers {
        if segment.p_type.get(object::Endianness::Little) == 1
        /* is LOAD */
        {
            load_segments.push(segment.clone());
        }
    }

    let mut allocated_memory_ptrs: Vec<*mut c_void> = vec![];
    let mut base_address: usize = usize::MAX;

    eprintln!("Segments");
    eprintln!("# address size offset length flags");
    let mut i = 0;
    for load_segment in load_segments {
        let p_offset = load_segment.p_offset(object::Endianness::Little) as *mut c_void;
        let p_vaddr = load_segment.p_vaddr(object::Endianness::Little) as usize;
        let p_memsz = load_segment.p_memsz(object::Endianness::Little) as usize;
        let p_flags = load_segment.p_flags(object::Endianness::Little) as usize;
        let p_filesz = load_segment.p_filesz(object::Endianness::Little) as usize;

        let actual_addr = p_vaddr - (p_vaddr % unsafe { page_size } as usize);
        let actual_offset = p_offset as usize - (p_offset as usize % unsafe { page_size } as usize);

        let segment_perms = SegmentPerms::from_number(p_flags);

        eprintln!(
            "{} 0x{:x} {} 0x{:x} {} {}",
            i,
            p_vaddr,
            p_memsz,
            p_offset as usize,
            p_filesz,
            segment_perms.to_string()
        );
        i = i + 1;
        let p = unsafe {
            mmap(
                // ((p_offset as usize) + p_vaddr) as *mut c_void,
                actual_addr as *mut c_void,
                // pagesize as usize,
                p_memsz,
                ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
        };

        if p.is_err() {
            println!("{}", p.err().unwrap());
            std::process::exit(-1);
        }

        let p = p.unwrap_or_else(|_| panic!("couldn't allocate pointer"));

        // println!("\n\nfilesz: {}\nmemsz: {}\n\n", p_filesz, p_memsz);

        file.seek(SeekFrom::Start(p_offset as u64))
            .unwrap_or_else(|e| panic!("can't navigate in the file at the specified offset"));
        let mut segment = vec![0; p_filesz];
        file.read_exact(&mut segment)
            .unwrap_or_else(|e| panic!("can't read segment data"));

        unsafe {
            std::ptr::copy_nonoverlapping(segment.as_ptr(), p as *mut u8, p_filesz);
            mprotect(p, p_memsz, segment_perms.to_flags()).unwrap_or_else(|e| {
                panic!("Error when protecting: {}", e);
            });
        }

        let vaddr = load_segment.p_vaddr.get(object::Endianness::Little) as usize;
        if vaddr < base_address {
            base_address = vaddr;
        }

        allocated_memory_ptrs.push(p);
    }

    let mut load_sections: Vec<NerosSection> = vec![];

    let file = object::File::parse(&*data)
        .unwrap_or_else(|_| panic!("can't parse file with object crate"));
    for section in file.sections() {
        let neros_section = NerosSection {
            name: section
                .name()
                .unwrap_or_else(|_| panic!("can't resolve section's name"))
                .to_owned(),
            address: section.address(),
            size: section.size(),
            align: section.align(),
        };

        match neros_section.name.as_str() {
            ".text" | ".data" | ".data1" | ".rodata" => {
                load_sections.push(neros_section);
            }
            ".bss" => {
                load_sections.push(neros_section);
                // okay so here we got 1 thing that's diff from all the other sections
                // bss is for unintialized global variables
                // so that means they are initialized to their default (which in pure binary is 0)

                // now, to save space, we are not saving the 0's in the file itself
                // so p_memsz is gonna be bigger (well, it's gonna be different than 0)
                // all whilst p_filesz is gonna be 0

                // so, keeping this in mind, when you do try to copy stuff to it from file
                // good luck
            }
            _ => {}
        }
    }

    // for section in

    // // determine entry point
    eprintln!("Entry point {:x}", entry_point);
    eprintln!("Base address {:x}", base_address);

    // // register SIGSEGV handler
    let handler = SigHandler::SigAction(sigsegv_handler);
    let action = SigAction::new(handler, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &action) }.expect("Failed to set signal handler");

    // // run ELF using runner::exec_run
    // runner::exec_run(base_address as usize, entry_point as usize);

    Ok(runner::exec_run(base_address, entry_point))
    // Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        page_size = sysconf(PAGE_SIZE)
            .unwrap_or_else(|_| panic!("can't set global page_size"))
            .unwrap_or_else(|| panic!("can't set global page_size --- 2"))
    };
    // load ELF provided within the first argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <executable>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    exec(filename).unwrap_or_else(|_| panic!("can't execute file"));
    Ok(())
}