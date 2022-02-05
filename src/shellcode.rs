use crate::{Error, Result};
use exe::{
    Address, CCharString, ImageImportByName, ImportDirectory, TLSDirectory, Thunk, ThunkData,
    ThunkFunctions, PE,
};
use iced_x86::code_asm::*;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::DLL_PROCESS_ATTACH;

pub(crate) fn generate_importer64<'a>(pe: &'a PE, imagebase: usize) -> Result<Vec<u8>> {
    let import_dir = ImportDirectory::parse(pe)?;

    let kernel32 = unsafe { GetModuleHandleA("kernel32.dll\0".as_ptr() as _) };
    if kernel32.is_null() {
        return Err(Error::GetModuleHandle(unsafe { GetLastError() }));
    }

    let load_library = unsafe { GetProcAddress(kernel32, "LoadLibraryA\0".as_ptr() as _) };
    if load_library.is_null() {
        return Err(Error::GetProcAddress(unsafe { GetLastError() }));
    }

    let get_proc_address = unsafe { GetProcAddress(kernel32, "GetProcAddress\0".as_ptr() as _) };
    if get_proc_address.is_null() {
        return Err(Error::GetProcAddress(unsafe { GetLastError() }));
    }

    let mut a = CodeAssembler::new(64)?;
    a.mov(rbp, rsp)?;
    // 16-byte align the stack
    a.sub(rsp, 0x20)?;
    a.and(rsp, -0x10)?;
    a.mov(rsi, load_library as u64)?;
    let rsi_load_library = rsi;
    a.mov(rdi, get_proc_address as u64)?;
    let rdi_get_proc_address = rdi;

    let mut return_label = a.create_label();
    let mut string_data = vec![];
    let mut create_string = |a: &mut CodeAssembler, s: &'a str| {
        let label = a.create_label();
        string_data.push((label, s));
        ptr(label)
    };

    for desc in import_dir.descriptors {
        let s = create_string(&mut a, desc.get_name(pe)?.as_str());
        a.lea(rcx, s)?;
        a.call(rsi_load_library)?;

        a.test(rax, rax)?;
        let mut success_label = a.create_label();
        a.jnz(success_label)?;
        a.inc(rax)?;
        a.jmp(return_label)?;
        a.set_label(&mut success_label)?;

        a.mov(rbx, rax)?;
        let rbx_module_handle = rbx;

        for (thunk, rva) in desc
            .get_lookup_thunks(pe)?
            .into_iter()
            .zip((desc.first_thunk.0..).step_by(8))
        {
            let thunk = if let Thunk::Thunk64(inner) = thunk {
                inner
            } else {
                panic!()
            };
            match thunk.parse_import() {
                ThunkData::ImportByName(v) => {
                    let s = create_string(&mut a, ImageImportByName::parse(pe, v)?.name.as_str());
                    a.lea(rdx, s)?;
                }
                ThunkData::Ordinal(v) => {
                    assert!(v <= 0xffff);
                    a.mov(rdx, v as u64)?;
                }
                _ => return Err(Error::from(exe::Error::CorruptDataDirectory)),
            }
            a.mov(rcx, rbx_module_handle)?;
            a.call(rdi_get_proc_address)?;

            a.test(rax, rax)?;
            let mut success_label = a.create_label();
            a.jnz(success_label)?;
            a.inc(rax)?;
            a.jmp(return_label)?;
            a.set_label(&mut success_label)?;

            a.mov(qword_ptr(imagebase + rva as usize), rax)?;
        }
    }

    a.xor(rax, rax)?;
    a.set_label(&mut return_label)?;
    a.mov(rsp, rbp)?;
    a.ret()?;

    for (mut label, s) in string_data {
        a.set_label(&mut label)?;
        a.db(s.as_bytes())?;
        a.db(&[0])?;
    }

    Ok(a.assemble(0)?)
}

pub(crate) fn generate_caller64(pe: &PE, imagebase: usize) -> Result<Vec<u8>> {
    let nt_headers = pe.get_valid_nt_headers_64()?;
    let entry = imagebase as u64 + nt_headers.optional_header.address_of_entry_point.0 as u64;

    let tls_dir = if let TLSDirectory::TLS64(inner) = TLSDirectory::parse(pe)? {
        inner
    } else {
        panic!();
    };

    let mut a = CodeAssembler::new(64)?;

    a.mov(rbp, rsp)?;
    // 16-byte align the stack
    a.sub(rsp, 0x20)?;
    a.and(rsp, -0x10)?;

    for callback in tls_dir.get_callbacks(pe)? {
        a.xor(r8, r8)?;
        a.mov(rdx, DLL_PROCESS_ATTACH as u64)?;
        a.mov(rcx, imagebase as u64)?;
        a.call(imagebase as u64 + callback.as_rva(pe)?.0 as u64)?;
    }

    a.xor(r8, r8)?;
    a.mov(rdx, DLL_PROCESS_ATTACH as u64)?;
    a.mov(rcx, imagebase as u64)?;
    a.call(entry)?;

    a.xor(rax, rax)?;
    a.mov(rsp, rbp)?;
    a.ret()?;

    Ok(a.assemble(0)?)
}
