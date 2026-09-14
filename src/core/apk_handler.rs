use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::DeflateDecoder;
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct DexEntry {
    pub name: String,
    pub uncomp_size: u32,
    pub comp_size: u32,
    pub local_header_off: u32,
    pub comp_method: u16,
}

pub struct ApkHandler {
    mmap: Mmap,
}

impl ApkHandler {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        Ok(Self { mmap })
    }

    pub fn mmap(&self) -> &Mmap {
        &self.mmap
    }

    fn find_eocd(&self) -> Option<usize> {
        let buf = &self.mmap;
        let search_start = buf.len().saturating_sub(65536 + 22);
        
        // Search backwards
        for i in (search_start..=(buf.len().saturating_sub(22))).rev() {
            if buf[i..i+4] == [0x50, 0x4b, 0x05, 0x06] {
                return Some(i);
            }
        }
        None
    }

    pub fn get_dex_entries(&self) -> Result<Vec<DexEntry>> {
        let eocd_idx = self.find_eocd().ok_or_else(|| anyhow!("EOCD not found"))?;
        let cd_off = (&self.mmap[eocd_idx + 16..eocd_idx + 20]).read_u32::<LittleEndian>()? as usize;
        let cd_size = (&self.mmap[eocd_idx + 12..eocd_idx + 16]).read_u32::<LittleEndian>()? as usize;
        let cd_end = cd_off + cd_size;

        if cd_end > self.mmap.len() {
            return Err(anyhow!("Invalid Central Directory offset/size"));
        }

        let mut entries = Vec::new();
        let mut pos = cd_off;

        while pos + 46 <= cd_end {
            let buf = &self.mmap;
            if buf[pos..pos+4] != [0x50, 0x4b, 0x01, 0x02] {
                break;
            }

            let name_len = (&buf[pos + 28..pos + 30]).read_u16::<LittleEndian>()? as usize;
            let extra_len = (&buf[pos + 30..pos + 32]).read_u16::<LittleEndian>()? as usize;
            let comment_len = (&buf[pos + 32..pos + 34]).read_u16::<LittleEndian>()? as usize;
            let comp_method = (&buf[pos + 10..pos + 12]).read_u16::<LittleEndian>()?;
            let comp_size = (&buf[pos + 20..pos + 24]).read_u32::<LittleEndian>()?;
            let uncomp_size = (&buf[pos + 24..pos + 28]).read_u32::<LittleEndian>()?;
            let local_header_off = (&buf[pos + 42..pos + 46]).read_u32::<LittleEndian>()?;

            let name_start = pos + 46;
            let name_end = name_start + name_len;
            
            if name_end <= cd_end {
                let name_bytes = &buf[name_start..name_end];
                if name_bytes.ends_with(b".dex") && !name_bytes.contains(&b'/') {
                    if let Ok(name) = std::str::from_utf8(name_bytes) {
                        entries.push(DexEntry {
                            name: name.to_string(),
                            uncomp_size,
                            comp_size,
                            local_header_off,
                            comp_method,
                        });
                    }
                }
            }
            
            pos = name_end + extra_len + comment_len;
        }

        Ok(entries)
    }

    pub fn inflate_dex(&self, entry: &DexEntry) -> Result<Vec<u8>> {
        let lh_off = entry.local_header_off as usize;
        let buf = &self.mmap;

        if lh_off + 30 > buf.len() || buf[lh_off..lh_off+4] != [0x50, 0x4b, 0x03, 0x04] {
            return Err(anyhow!("Invalid local header signature"));
        }

        let name_len = (&buf[lh_off + 26..lh_off + 28]).read_u16::<LittleEndian>()? as usize;
        let extra_len = (&buf[lh_off + 28..lh_off + 30]).read_u16::<LittleEndian>()? as usize;

        let data_off = lh_off + 30 + name_len + extra_len;
        let comp_size = entry.comp_size as usize;

        if data_off + comp_size > buf.len() {
            return Err(anyhow!("Compressed data out of bounds"));
        }

        let comp_data = &buf[data_off..data_off + comp_size];

        match entry.comp_method {
            0 => Ok(comp_data.to_vec()), // STORE
            8 => {
                // DEFLATE
                let mut decoder = DeflateDecoder::new(comp_data);
                let mut out = Vec::with_capacity(entry.uncomp_size as usize);
                decoder.read_to_end(&mut out)?;
                
                if out.len() != entry.uncomp_size as usize {
                    return Err(anyhow!("Size mismatch: expected {}, got {}", entry.uncomp_size, out.len()));
                }
                Ok(out)
            },
            m => Err(anyhow!("Unsupported compression method: {}", m)),
        }
    }
}
