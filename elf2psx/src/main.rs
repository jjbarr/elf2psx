use anyhow::{anyhow, bail, Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use goblin::{
    elf::header::{EM_MIPS, EM_MIPS_RS3_LE, ET_EXEC},
    elf::program_header::{PF_W, PF_X, PT_LOAD},
    Object,
};
use parse_int::parse;
#[cfg(target_family = "unix")]
use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::OsString,
    fs,
    fs::File,
    io::{BufWriter, Seek, SeekFrom, Write},
    path::PathBuf,
};
static USAGE: &'static str = include_str!("usage.txt");
static PSXMAGIC: &'static [u8] = b"PS-X EXE\0\0\0\0\0\0\0\0";

struct Args {
    srcfi: Option<PathBuf>,
    dstfi: Option<PathBuf>,
    strip_ro: bool,
    sp: u32,
    gp: u32,
    // this might seem wrong, because the region str is embedded into the
    // binary. But OsStrings are guaranteed to be bytestrings, not unicode
    // strings. They just may not be validly encoded.
    //
    // if for whaterver reason you *want* to put garbage into your region
    // marker, who am I to disagree?
    region: Option<OsString>,
}

fn parse_num_for_flag(flag: char, arg: OsString) -> Result<u32> {
    let argstring = arg.into_string().map_err(|_| {
        anyhow!("option requires a numerical argument -- {}", flag)
    })?;
    parse::<u32>(&argstring)
        .with_context(|| format!("{}: not a number", &argstring))
}

fn parse_args(args: &mut Args) -> Result<()> {
    use lexopt::prelude::*;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next().context("error parsing arguments")? {
        match arg {
            Value(fi) => {
                if fi == "" {
                    bail!("provided filename cannot be empty string.");
                }
                let pth = PathBuf::from(fi);
                if args.srcfi.is_none() {
                    args.srcfi = Some(pth);
                } else if args.dstfi.is_none() {
                    args.dstfi = Some(pth);
                } else {
                    bail!("too many files provided.\n{}", USAGE);
                }
            }
            Short('r') => {
                args.region = Some(parser.value()?);
            }
            Short('S') => args.strip_ro = true,
            Short('s') => {
                args.sp = parse_num_for_flag('s', parser.value()?)?;
            }
            Short('g') => {
                args.gp = parse_num_for_flag('g', parser.value()?)?;
            }

            _ => bail!("{}\n{}", arg.unexpected(), USAGE),
        }
    }
    Ok(())
}

// The information used to construct this was taken from Martin Korth's PSX-SPX,
// pcsx-redux's internal definitions (src/mips/common/psxlibc/psxexe.h), and
// through examining lameguy64's elf2x, spicyjpeg's convertExecutable.py, and
// psxsdk's elf2exe. Some of this information may have originally been taken
// from the documentation of the original PSY-Q SDK. I have been given no reason
// to believe this to be the case, but it is a possibility. pcsx-redux's efforts
// are based upon reverse-engineering a PSX BIOS.
#[repr(C)]
struct PSXExeHeader<'a> {
    //magic, followed by eight bytes of padding here
    // >
    pc: u32,
    gp: u32,
    text_addr: u32,
    text_size: u32,
    // four words here for data/bss start/size, which we do not use.
    // >
    // it seems like exec breaks if you don't provide a stack address.
    // but unless you're chainloading an exe from CDROM using BIOS calls
    // (and really, why would you do something like that to yourself),
    // system.cnf will take care of it.
    stack_start: u32,
    // one word here for stack size, which nobody seems to ever set.
    // >
    // 20-byte region reserved for saved registers during Exec
    // >
    // region string goes here, followed by 1972-len bytes to make the header
    // 2048 bytes.
    // >
    region: &'a [u8],
}

impl PSXExeHeader<'_> {
    /// Writes out a PSX EXE header to `stream`, which must support Seek and
    /// therefore probably must be a file. Note that this function deliberately
    /// writes a sparse file and won't work on systems that do not support
    /// that. However, I am not aware of any such systems.
    fn write<T: Write + Seek>(
        &self,
        stream: &mut T,
    ) -> Result<(), anyhow::Error> {
        let startpoint = stream.stream_position()?;
        stream.write_all(PSXMAGIC)?;
        stream.write_u32::<LittleEndian>(self.pc)?;
        stream.write_u32::<LittleEndian>(self.gp)?;
        stream.write_u32::<LittleEndian>(self.text_addr)?;
        stream.write_u32::<LittleEndian>(self.text_size)?;
        stream.seek(SeekFrom::Current(16))?;
        stream.write_u32::<LittleEndian>(self.stack_start)?;
        stream.seek(SeekFrom::Current(24))?;
        stream.write_all(self.region)?;
        stream.seek(SeekFrom::Start(startpoint + 2048))?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = {
        let mut args = Args {
            srcfi: None,
            dstfi: None,
            region: None,
            sp: 0,
            gp: 0,
            strip_ro: false,
        };
        parse_args(&mut args)?;
        args
    };
    let srcpth = args
        .srcfi
        .ok_or_else(|| anyhow!("No input file provided"))?;
    let dstpth = if args.dstfi.is_none() {
        let mut dstpth = srcpth.clone();
        if !dstpth.set_extension("exe") {
            bail!("unable to infer output file name from input file");
        }
        dstpth
    } else {
        args.dstfi.unwrap()
    };
    let elf_bytes = &fs::read(&srcpth).context("could not read input file")?;
    let inelf =
        match Object::parse(elf_bytes).context("failed to parse input file")? {
            Object::Elf(e) => e,
            _ => bail!("input file is not an ELF binary"),
        };
    // basic sanity checks on the actual ELF file.
    if inelf.is_64
        || !inelf.little_endian
        || inelf.header.e_type != ET_EXEC
        || (inelf.header.e_machine != EM_MIPS
            && inelf.header.e_machine != EM_MIPS_RS3_LE)
    {
        bail!("input ELF must be a 32-bit little-endian MIPS executable.");
    }

    //we know the elf is 32-bit
    let initpc = inelf.header.e_entry as u32;

    // and now we must sort the PT_LOAD segments by vaddr/paddr. I don't know
    // why you'd ever have more than one PT_LOAD segment for this system, but
    // Just In Case the linker and/or ldscript is being weird.
    //
    // This can be fixed up and removed later, because we only need the
    // min/maxaddr and optionally the ro sections filtered out. sorting is
    // unnecessary.
    let phdrs = {
        let mut phdrs = inelf
            .program_headers
            .iter()
            .filter(|phdr| {
                phdr.p_type == PT_LOAD
                    && (!args.strip_ro
                        || (phdr.p_flags & PF_W) != 0
                        || (phdr.p_flags & PF_X) != 0)
            })
            .collect::<Vec<_>>();
        phdrs.sort_unstable_by(|x, y| x.p_vaddr.cmp(&y.p_vaddr));
        phdrs
    };
    if phdrs.len() == 0 {
        bail!("input ELF must have at least one PT_LOAD segment.")
    }
    let minaddr = phdrs[0].p_vaddr as u32;
    let maxaddr = (phdrs[phdrs.len() - 1].p_vaddr
        + phdrs[phdrs.len() - 1].p_filesz) as u32;
    let loadsz = maxaddr - minaddr;
    if loadsz > 0x1f_0000 {
        //That's not even the advertised 2MiB. Bah.
        eprintln!("WARNING: EXE won't fit in retail console RAM");
    }
    if (minaddr & 0xff_ffff) < 0x1_0000 {
        //mask away kseg0/kseg1/kuseg differences before the compare.
        eprintln!("WARNING: EXE is mapped into PSX kernel memory.");
    }

    //round up to the nearest multiple of 2048.
    let padded_textsz = (loadsz + 0x7ff) & !0x7ff;

    //turn the region string into bytes
    let region = args.region.unwrap_or(OsString::new());
    //ugggh. Ugly hack to deal with the lack of support for cfg in expressions.
    #[cfg(target_family = "unix")]
    let region_bytes = region.as_bytes();
    // NOTE: this hasn't been tested. It should work, in theory, but I do not
    // guarantee it.
    #[cfg(target_family = "windows")]
    let region_bytes = {
        if !region.is_ascii() {
            bail!(
                "non-ascii region strings on Windows are ambigious and \
                   therefore not permitted."
            )
        }
        region.to_str().unwrap().as_bytes()
    };

    if region_bytes.len() > 1972 {
        bail!("Region string too long!");
    }

    let header = PSXExeHeader {
        pc: initpc,
        gp: args.gp,
        text_addr: minaddr,
        text_size: padded_textsz,
        stack_start: args.sp,
        region: region_bytes,
    };

    let mut exe_text = vec![];
    exe_text.resize(padded_textsz as usize, 0);

    for phdr in phdrs.iter() {
        let elf_start = phdr.p_offset as usize;
        let textslice =
            &elf_bytes[elf_start..elf_start + phdr.p_filesz as usize];
        let exe_start = phdr.p_vaddr as usize - minaddr as usize;
        exe_text[exe_start..exe_start + phdr.p_filesz as usize]
            .copy_from_slice(textslice);
    }

    let mut dstfi = BufWriter::new(
        File::create(dstpth).context("could not create EXE file")?,
    );

    header.write(&mut dstfi)?;
    dstfi.write_all(&exe_text)?;
    dstfi.flush()?;

    Ok(())
}
