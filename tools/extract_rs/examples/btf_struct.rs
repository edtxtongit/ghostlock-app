//! Reverse-engineering helper: dump BTF member offsets for named structs from
//! an embedded kernel image, so route geometry can be checked against the
//! image instead of a family default.
//!
//! usage: cargo run --release --example btf_struct -- <boot.img> <struct>...

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::{Btf, BtfType};

fn dump(btf: &Btf, ty: &BtfType, base: u64, depth: usize) {
    for member in &ty.members {
        let offset = base.wrapping_add(u64::from(member.bit_offset / 8));
        let name = if member.name.is_empty() {
            "<anon>"
        } else {
            member.name.as_str()
        };
        let resolved = btf.resolve(member.type_id);
        let type_name = resolved.map(|t| t.name.clone()).unwrap_or_default();
        let size = btf.type_size(member.type_id).unwrap_or(0);
        let kind = resolved.map(|t| t.kind).unwrap_or(u32::MAX);
        println!(
            "{:indent$}{} @ +0x{:x} size=0x{:x} kind={} type={}",
            "",
            name,
            offset,
            size,
            kind,
            type_name,
            indent = depth * 2
        );
        if member.name.is_empty() {
            if let Some(child) = resolved {
                dump(btf, child, offset, depth + 1);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: btf_struct <boot.img> <struct>...");
        std::process::exit(2);
    }
    let boot = BootImage::load(Path::new(&args[0])).expect("load boot image");
    let (_, blob) = boot.embedded_btf_at().expect("embedded BTF");
    let btf = Btf::new(&blob).expect("parse BTF");
    for name in &args[1..] {
        match btf.named_struct(name) {
            Some(ty) => {
                println!(
                    "struct {} size=0x{:x}",
                    name,
                    btf.size(name).unwrap_or(0)
                );
                dump(&btf, ty, 0, 1);
            }
            None => println!("struct {}: not found", name),
        }
    }
}
