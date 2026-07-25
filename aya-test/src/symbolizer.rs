//! Symbol resolution for flame-graph generation.
//!
//! [`Symbolizer`] resolves raw instruction pointers to human-readable
//! function names by consulting `/proc/{pid}/maps` and ELF symbol tables.

use std::collections::HashMap;
use std::path::PathBuf;

/// A parsed line from `/proc/{pid}/maps`.
#[derive(Clone)]
pub struct MemMapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub path: PathBuf,
}

/// Resolves instruction pointers to human-readable symbol names.
///
/// Uses `/proc/{pid}/maps` to map IP → (binary, file-offset), then parses
/// the ELF symbol table of the binary via [`goblin`] to find the nearest
/// function symbol.  Results are cached per binary.
pub struct Symbolizer {
    mappings: Vec<MemMapping>,
    // cache: binary path → Vec<(address, name)> sorted by address
    symbol_cache: HashMap<PathBuf, Vec<(u64, String)>>,
    // kernel symbols loaded from /proc/kallsyms
    ksyms: Vec<(u64, String)>,
}

impl Symbolizer {
    /// Creates a new symbolizer for `pid` by parsing `/proc/{pid}/maps`.
    pub fn new(pid: u32) -> Self {
        Self {
            mappings: Self::parse_maps(pid),
            symbol_cache: HashMap::new(),
            ksyms: Self::load_kallsyms(),
        }
    }

    /// Reads `/proc/kallsyms` into sorted `(address, name)` pairs.
    fn load_kallsyms() -> Vec<(u64, String)> {
        let mut syms: Vec<_> = std::fs::read_to_string("/proc/kallsyms")
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(4, ' ');
                let addr_str = parts.next()?;
                parts.next()?; // skip type char
                let name = parts.next().filter(|n| !n.is_empty())?;
                let addr = u64::from_str_radix(addr_str, 16).ok()?;
                Some((addr, name.to_string()))
            })
            .collect();
        syms.sort_by_key(|(a, _)| *a);
        syms
    }

    fn parse_maps(pid: u32) -> Vec<MemMapping> {
        let path = format!("/proc/{}/maps", pid);
        let mut maps: Vec<_> = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    return None;
                }
                let addrs: Vec<&str> = parts[0].split('-').collect();
                if addrs.len() != 2 {
                    return None;
                }
                let start = u64::from_str_radix(addrs[0], 16).ok()?;
                let end = u64::from_str_radix(addrs[1], 16).ok()?;
                let offset = u64::from_str_radix(parts[2], 16).ok()?;
                let path_name = parts[5];
                if start == 0 || path_name.starts_with('[') {
                    return None;
                }
                Some(MemMapping {
                    start,
                    end,
                    offset,
                    path: PathBuf::from(path_name),
                })
            })
            .collect();
        maps.sort_by_key(|m| m.start);
        maps
    }

    /// Loads (or retrieves from cache) sorted `(address, name)` pairs for
    /// the ELF binary at `path`.
    fn load_syms(&mut self, path: &PathBuf) -> &Vec<(u64, String)> {
        if !self.symbol_cache.contains_key(path) {
            let mut syms = Vec::new();
            if let Ok(data) = std::fs::read(path) {
                if let Ok(elf) = goblin::elf::Elf::parse(&data) {
                    // Prefer .symtab, then fall back to .dynsym for stripped binaries
                    let use_dynsym = elf.syms.is_empty();
                    let symtab = if use_dynsym { &elf.dynsyms } else { &elf.syms };
                    let strtab = if use_dynsym { &elf.dynstrtab } else { &elf.strtab };
                    syms = symtab
                        .iter()
                        .filter(|sym| sym.st_value != 0 && sym.st_shndx != 0)
                        .filter_map(|sym| {
                            let name = strtab.get_at(sym.st_name)?;
                            if name.is_empty() {
                                None
                            } else {
                                Some((sym.st_value, name.to_string()))
                            }
                        })
                        .collect();
                }
            }
            syms.sort_by_key(|(a, _)| *a);
            self.symbol_cache.insert(path.clone(), syms);
        }
        self.symbol_cache.get(path).unwrap()
    }

    /// Resolves a single user-space instruction pointer to a symbol name.
    pub fn resolve(&mut self, ip: u64) -> String {
        let (file_off, path) = {
            let mapping = match self.mappings.binary_search_by_key(&ip, |m| m.start) {
                Ok(i) => &self.mappings[i],
                Err(i) if i > 0 => {
                    let m = &self.mappings[i - 1];
                    if ip >= m.start && ip < m.end {
                        m
                    } else {
                        return format!("0x{:x}", ip);
                    }
                }
                _ => return format!("0x{:x}", ip),
            };
            (ip - mapping.start + mapping.offset, mapping.path.clone())
        };

        let syms = self.load_syms(&path);

        let idx = match syms.binary_search_by_key(&file_off, |(a, _)| *a) {
            Ok(i) => i,
            Err(i) if i > 0 => i - 1,
            _ => {
                let fname = path
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default();
                return format!("{}!+0x{:x}", fname, file_off);
            }
        };

        if idx < syms.len() {
            let (sym_addr, name) = &syms[idx];
            let next_addr = syms.get(idx + 1).map(|(a, _)| *a).unwrap_or(u64::MAX);
            if file_off >= *sym_addr && file_off < next_addr {
                return name.clone();
            }
        }

        let fname = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("{}!+0x{:x}", fname, file_off)
    }

    /// Resolves a kernel-space IP via `/proc/kallsyms`.
    pub fn resolve_kernel(&self, ip: u64) -> String {
        let idx = match self.ksyms.binary_search_by_key(&ip, |(a, _)| *a) {
            Ok(i) => i,
            Err(i) if i > 0 => i - 1,
            _ => return format!("[k] 0x{:x}", ip),
        };
        if idx < self.ksyms.len() {
            let (ks_addr, name) = &self.ksyms[idx];
            let next_addr = self.ksyms
                .get(idx + 1)
                .map(|(a, _)| *a)
                .unwrap_or(u64::MAX);
            if ip >= *ks_addr && ip < next_addr {
                return format!("[k] {}", name);
            }
        }
        format!("[k] 0x{:x}", ip)
    }
}
