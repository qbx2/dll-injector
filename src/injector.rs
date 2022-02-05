use crate::deferred::Deferred;
use crate::shellcode::{generate_caller64, generate_importer64};
use std::mem::transmute;
use winapi::shared::minwindef::{DWORD, LPCVOID, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, GetExitCodeThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("OpenProcess failed: {0}")]
    OpenProcess(u32),

    #[error("WriteProcessMemory failed: {0}")]
    WriteProcessMemory(u32),

    #[error("GetModuleHandle failed: {0}")]
    GetModuleHandle(u32),

    #[error("GetProcAddress failed: {0}")]
    GetProcAddress(u32),

    #[error("CreateRemoteThread failed: {0}")]
    CreateRemoteThread(u32),

    #[error("WaitForSingleObject failed: {0}")]
    WaitForSingleObject(u32, u32),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Exe(#[from] exe::Error),

    #[error("Invalid PE File")]
    InvalidFile,

    #[error(transparent)]
    Iced(#[from] iced_x86::IcedError),

    #[error("Shellcode returned: {0}")]
    ShellcodeFailed(u32),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) unsafe fn open_process(deferred: &mut Deferred, pid: DWORD) -> Result<HANDLE> {
    let handle = OpenProcess(
        winapi::um::winnt::PROCESS_ALL_ACCESS,
        winapi::shared::minwindef::FALSE,
        pid,
    );

    if handle.is_null() {
        return Err(Error::OpenProcess(GetLastError()));
    }

    deferred.push(move || {
        CloseHandle(handle);
    });

    Ok(handle)
}

unsafe fn virtual_alloc_ex(
    deferred: &mut Deferred,
    h_process: HANDLE,
    size: usize,
    protection: DWORD,
) -> Result<LPVOID> {
    let buf = VirtualAllocEx(h_process, 0 as _, size, MEM_COMMIT, protection);

    if buf.is_null() {
        return Err(Error::OpenProcess(GetLastError()));
    }

    deferred.push(move || {
        VirtualFreeEx(h_process, buf, 0, MEM_RELEASE);
    });

    Ok(buf)
}

unsafe fn create_remote_thread_and_wait(
    deferred: &mut Deferred,
    h_process: HANDLE,
    address: LPCVOID,
    param: LPVOID,
) -> Result<u32> {
    let h_thread = CreateRemoteThread(
        h_process,
        0 as _,
        0,
        Some(transmute(address)),
        param,
        0,
        0 as _,
    );
    if h_thread.is_null() {
        return Err(Error::CreateRemoteThread(GetLastError()));
    }

    deferred.push(move || {
        CloseHandle(h_thread);
    });

    let ret = WaitForSingleObject(h_thread, INFINITE);
    if ret != 0 {
        return Err(Error::WaitForSingleObject(ret, GetLastError()));
    }

    let mut exit_code = 0;
    GetExitCodeThread(h_thread, &mut exit_code as _);

    Ok(exit_code)
}

pub(crate) unsafe fn inject_dll_manual_map(
    _deferred: &mut Deferred,
    h_process: HANDLE,
    file_buf: &mut [u8],
) -> Result<()> {
    // we don't want to dealloc memory on success, so manage own deferred
    let mut owned_deferred = Deferred::new();
    let deferred = &mut owned_deferred;

    // NOTE: exe::Buffer implementation is not safe, so should take care of it
    let file_buf2 = file_buf.to_vec();
    let pe = exe::PE {
        pe_type: exe::PEType::Disk,
        buffer: exe::Buffer::new(&file_buf2),
    };
    let nt_headers = pe.get_valid_nt_headers_64()?;

    if nt_headers.signature != 0x4550 {
        return Err(Error::InvalidFile);
    }

    if !nt_headers
        .file_header
        .characteristics
        .contains(exe::FileCharacteristics::DLL)
    {
        return Err(Error::InvalidFile);
    }

    let image_buf = virtual_alloc_ex(
        deferred,
        h_process,
        nt_headers.optional_header.size_of_image as _,
        PAGE_EXECUTE_READWRITE,
    )?;

    let relocation_dir = exe::RelocationDirectory::parse(&pe)?;
    let mut relocated_pe = exe::PE {
        pe_type: exe::PEType::Disk,
        buffer: exe::Buffer::new(file_buf),
    };
    relocation_dir.relocate(&mut relocated_pe, image_buf as _)?;

    // TODO: Do we need this? provide options
    write_process_memory(h_process, file_buf.as_ptr() as _, image_buf, 0x1000)?;

    for section in relocated_pe.get_section_table()? {
        let src = section.read(&relocated_pe)?;
        write_process_memory(
            h_process,
            src.as_ptr() as _,
            (image_buf as usize + section.virtual_address.0 as usize) as _,
            src.len(),
        )?;
    }

    {
        let shellcodes = [
            generate_importer64(&pe, image_buf as _)?,
            generate_caller64(&pe, image_buf as _)?,
        ];

        let mut deferred = Deferred::new();

        let shellcode_buf = virtual_alloc_ex(
            &mut deferred,
            h_process,
            shellcodes.iter().map(|v| v.len()).max().unwrap(),
            PAGE_EXECUTE_READWRITE,
        )?;

        for shellcode in shellcodes {
            write_process_memory(
                h_process,
                shellcode.as_ptr() as _,
                shellcode_buf,
                shellcode.len(),
            )?;

            let ret =
                create_remote_thread_and_wait(&mut deferred, h_process, shellcode_buf, 0 as _)?;
            if ret != 0 {
                return Err(Error::ShellcodeFailed(ret));
            }
        }
    }

    deferred.clear();

    Ok(())
}

unsafe fn write_process_memory(
    h_process: HANDLE,
    src: LPCVOID,
    dst: LPVOID,
    size: usize,
) -> Result<()> {
    let mut num_written = 0;
    let ret = WriteProcessMemory(h_process, dst, src, size, &mut num_written as _);

    if ret == 0 {
        return Err(Error::WriteProcessMemory(GetLastError()));
    }

    if size != num_written {
        return Err(Error::WriteProcessMemory(0));
    }

    Ok(())
}

pub(crate) unsafe fn inject_dll_load_library(
    deferred: &mut Deferred,
    h_process: HANDLE,
    filename: &str,
) -> Result<()> {
    // make sure zero terminated
    let mut filename = filename.to_string();
    filename.push('\0');

    assert!(filename.len() < 0x1000);
    let buf = virtual_alloc_ex(deferred, h_process, 0x1000, PAGE_READWRITE)?;

    write_process_memory(h_process, filename.as_ptr() as _, buf, filename.len())?;

    let kernel32 = GetModuleHandleA("kernel32.dll\0".as_ptr() as _);
    if kernel32.is_null() {
        return Err(Error::GetModuleHandle(GetLastError()));
    }

    let load_library = GetProcAddress(kernel32, "LoadLibraryA\0".as_ptr() as _);
    if load_library.is_null() {
        return Err(Error::GetProcAddress(GetLastError()));
    }

    create_remote_thread_and_wait(deferred, h_process, load_library as _, buf)?;

    Ok(())
}
