use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages
    let si_addr = unsafe { (*info).si_addr() };

    if is_invalid_access(address) {
        eprintln!("Invalid memory access at address: {:#x}", address);
        std::process::exit(-200);
    } else {
        // Map the faulting page into memory with appropriate permissions
        unsafe {
            mmap(
                address as *mut c_void,
                page_size as usize,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE, 
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            ).unwrap_or_else(|err| {
                // eprintln!("error to map page: {:#?}", err);
                std::process::exit(-1);
            });
        }
    }
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // read ELF segments
    let data = std::fs::read(filename)?;
    let elf = elf::FileHeader32::<Endianness>::parse(&*data)?;
    let endian = elf.endian()?;

    let entry_point = elf.e_entry.get(endian) as usize;
    let program_headers = elf.program_headers(endian, data.as_slice())?;
    
    // print segments

    eprintln!("Segments:");
    for segment in program_headers {
        eprintln!("Segment type: {:#x}, vaddr: {:#x}, paddr: {:#x}", 
            segment.p_type.get(endian), 
            segment.p_vaddr.get(endian), 
            segment.p_paddr.get(endian));
    }
    for segment in program_headers {
        if segment.p_type.get(endian) == elf::PT_LOAD {
            let memsz = segment.p_memsz.get(endian) as usize;
            let filesz = segment.p_filesz.get(endian) as usize;

            let vaddr = segment.p_vaddr.get(endian) as usize;

            unsafe {
                let ptr = mmap(
                    vaddr as *mut c_void,
                    memsz,
                    ProtFlags::PROT_WRITE, // Adjust as per segment flags
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                    -1,
                    0,
                )?;

            
                if filesz > 0 {
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr().add(segment.p_offset.get(endian) as usize),
                        ptr as *mut u8,
                        filesz
                    );
                }
            }
        }
    }

  
    let handler = SigHandler::SigAction(sigsegv_handler);
    let action = SigAction::new(handler, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &action)?; }

    runner::exec_run(0, entry_point); 

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // load ELF provided within the first argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <executable>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    exec(filename)?;
    Ok(())
}