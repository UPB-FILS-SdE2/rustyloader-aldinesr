use nix::libc::{siginfo_t, mmap, munmap};
use nix::sys::mman::{MapFlags, ProtFlags, mprotect};
use nix::sys::signal::{sigaction, SigAction, SigHandler, SaFlags, SigSet, Signal};
use nix::unistd::{sysconf, getpid, SysconfVar::PAGE_SIZE};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_void};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::fs;
use std::error::Error;
use object::{Object, ObjectSection, ObjectSegment};
use object::read::elf::{FileHeader32, ElfFile};
use object::{elf, Endianness, LittleEndian};

mod permissions;
mod runner;

static mut GLOBAL_PAGE_SIZE: i32 = 0;

extern "C" fn custom_sigsegv_handler(signal: c_int, info: *mut siginfo_t, context: *mut c_void) {
    let fault_address = unsafe { (*info).si_addr() } as usize;
    if fault_address < 0x08048000 || fault_address > 0xC0000000 {
        eprintln!(
            "Segmentation fault at 0x{:x}, page 0x{:x} (invalid access)",
            fault_address,
            fault_address & !(unsafe { GLOBAL_PAGE_SIZE } as usize - 1)
        );
        std::process::exit(56);
    } else {
        let error_code = unsafe { (*info).si_code };
        match error_code {
            1 => {
                eprintln!(
                    "Segmentation fault at 0x{:x}, page 0x{:x} (invalid mapping)",
                    fault_address,
                    fault_address & !(unsafe { GLOBAL_PAGE_SIZE } as usize - 1)
                );
                std::process::exit(56);
            }
            2 => {
                eprintln!(
                    "Segmentation fault at 0x{:x}, page 0x{:x} (protection violation)",
                    fault_address,
                    fault_address & !(unsafe { GLOBAL_PAGE_SIZE } as usize - 1)
                );
                std::process::exit(56);
            }
            _ => eprintln!("Unexpected SEGV code: {}", error_code),
        }

        unsafe {
            mmap(
                fault_address as *mut c_void,
                GLOBAL_PAGE_SIZE as usize,
                ProtFlags::all(),
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            ).unwrap_or_else(|_| {
                eprintln!(
                    "Segmentation fault at 0x{:x}, page 0x{:x} (access failure)",
                    fault_address,
                    fault_address & !(GLOBAL_PAGE_SIZE as usize - 1)
                );
                std::process::exit(56);
            });
        }
    }
}

fn describe_segment(header: &elf::ProgramHeader32<Endianness>) -> String {
    format!(
        "Program Header:
    Type: 0x{:x},
    Offset: 0x{:x},
    Virtual Address: 0x{:x},
    Physical Address: 0x{:x},
    File Size: 0x{:x},
    Memory Size: 0x{:x},
    Flags: 0x{:x},
    Alignment: 0x{:x}",
        header.p_type.get(Endianness::Little),
        header.p_offset.get(Endianness::Little),
        header.p_vaddr.get(Endianness::Little),
        header.p_paddr.get(Endianness::Little),
        header.p_filesz.get(Endianness::Little),
        header.p_memsz.get(Endianness::Little),
        header.p_flags.get(Endianness::Little),
        header.p_align.get(Endianness::Little),
    )
}

struct MemorySection {
    section_name: String,
    section_address: u64,
    section_size: u64,
    section_alignment: u64,
}

impl core::fmt::Debug for MemorySection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySection")
            .field("Name", &self.section_name)
            .field("Address", &format_args!("0x{:X}", self.section_address))
            .field("Size", &format_args!("0x{:X}", self.section_size))
            .field("Alignment", &format_args!("0x{:X}", self.section_alignment))
            .finish()
    }
}

fn load_and_execute(filename: &str) -> Result<(), Box<dyn Error>> {
    let mut elf_file = fs::File::open(filename)?;
    let file_descriptor = elf_file.as_raw_fd();
    let file_data = fs::read(filename)?;
    let elf_header = elf::FileHeader32::<Endianness>::parse(&*file_data)?;
    let endian_type = elf_header.endian()?;

    let entry_address = elf_header.e_entry.get(Endianness::Little) as usize;
    let program_headers = elf_header.program_headers(endian_type, &file_data)
        .unwrap_or_else(|_| panic!("Failed to read program headers"));

    let mut load_segments: Vec<ProgramHeader32<Endianness>> = Vec::new();

    for header in program_headers {
        if header.p_type.get(Endianness::Little) == elf::PT_LOAD {
            load_segments.push(header.clone());
        }
    }

    let mut allocated_memory: Vec<*mut c_void> = Vec::new();
    let mut lowest_address: usize = usize::MAX;

    eprintln!("Loaded Segments:");
    eprintln!("# Address      Size     Offset   Length  Flags");

    for (index, segment) in load_segments.iter().enumerate() {
        let segment_offset = segment.p_offset(Endianness::Little) as *mut c_void;
        let segment_vaddr = segment.p_vaddr(Endianness::Little) as usize;
        let segment_memsz = segment.p_memsz(Endianness::Little) as usize;
        let segment_filesz = segment.p_filesz(Endianness::Little) as usize;
        let segment_flags = segment.p_flags(Endianness::Little) as usize;

        let page_aligned_vaddr = segment_vaddr - (segment_vaddr % unsafe { GLOBAL_PAGE_SIZE } as usize);
        let page_aligned_offset = segment_offset as usize - (segment_offset as usize % unsafe { GLOBAL_PAGE_SIZE } as usize);

        let segment_permissions = permissions::Permissions::from_flags(segment_flags);

        eprintln!(
            "{} 0x{:x} 0x{:x} 0x{:x} 0x{:x} {}",
            index,
            segment_vaddr,
            segment_memsz,
            segment_offset as usize,
            segment_filesz,
            segment_permissions.to_string()
        );

        let mapped_memory = unsafe {
            mmap(
                page_aligned_vaddr as *mut c_void,
                segment_memsz,
                ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
        };

        if let Err(error) = mapped_memory {
            eprintln!("Mapping error: {}", error);
            std::process::exit(-1);
        }

        let memory_ptr = mapped_memory.unwrap_or_else(|_| panic!("Failed to allocate memory"));

        elf_file.seek(SeekFrom::Start(segment_offset as u64))
            .unwrap_or_else(|error| panic!("Error seeking file: {}", error));

        let mut segment_data = vec![0; segment_filesz];
        elf_file.read_exact(&mut segment_data)
            .unwrap_or_else(|error| panic!("Error reading segment: {}", error));

        unsafe {
            std::ptr::copy_nonoverlapping(segment_data.as_ptr(), memory_ptr as *mut u8, segment_filesz);
            mprotect(memory_ptr, segment_memsz, segment_permissions.to_protection_flags()).unwrap_or_else(|error| {
                panic!("Memory protection error: {}", error);
            });
        }

        if segment_vaddr < lowest_address {
            lowest_address = segment_vaddr;
        }

        allocated_memory.push(memory_ptr);
    }

    let mut sections: Vec<MemorySection> = Vec::new();

    let parsed_file = object::File::parse(&*file_data)
        .unwrap_or_else(|_| panic!("Failed to parse ELF file"));

    for section in parsed_file.sections() {
        let mem_section = MemorySection {
            section_name: section.name().unwrap_or("").to_owned(),
            section_address: section.address(),
            section_size: section.size(),
            section_alignment: section.align(),
        };

        match mem_section.section_name.as_str() {
            ".text" | ".data" | ".rodata" | ".bss" => {
                sections.push(mem_section);
            }
            _ => {}
        }
    }

    eprintln!("Entry Point: 0x{:x}", entry_address);
    eprintln!("Base Address: 0x{:x}", lowest_address);

    let signal_handler = SigHandler::SigAction(custom_sigsegv_handler);
    let signal_action = SigAction::new(signal_handler, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &signal_action) }
        .expect("Failed to set signal handler");

    Ok(runner::execute(lowest_address, entry_address))
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        GLOBAL_PAGE_SIZE = sysconf(PAGE_SIZE)
            .expect("Unable to get page size")
            .expect("Unable to retrieve page size");
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <ELF file>", args[0]);
        std::process::exit(1);
    }

    let elf_filename = &args[1];
    load_and_execute(elf_filename).unwrap_or_else(|error| panic!("Execution failed: {}", error));
    Ok(())
}
