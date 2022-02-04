use crate::deferred::Deferred;
use std::mem::transmute;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE};

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
    Goblin(#[from] goblin::error::Error),
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
) -> Result<LPVOID> {
    let buf = VirtualAllocEx(h_process, 0 as _, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if buf.is_null() {
        return Err(Error::OpenProcess(GetLastError()));
    }

    deferred.push(move || {
        VirtualFreeEx(h_process, buf, 0, MEM_RELEASE);
    });

    Ok(buf)
}

pub(crate) unsafe fn inject_dll_manual_map(
    deferred: &mut Deferred,
    h_process: HANDLE,
    filename: &str,
) -> Result<()> {
    unimplemented!()
}

unsafe fn write_process_memory(
    h_process: HANDLE,
    src: LPVOID,
    dst: LPVOID,
    size: usize,
) -> Result<()> {
    let ret = WriteProcessMemory(h_process, dst, src, size, 0 as _);

    if ret == 0 {
        return Err(Error::WriteProcessMemory(GetLastError()));
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
    let buf = virtual_alloc_ex(deferred, h_process, 0x1000)?;

    write_process_memory(h_process, filename.as_mut_ptr() as _, buf, filename.len())?;

    let kernel32 = GetModuleHandleA("kernel32.dll\0".as_ptr() as _);
    if kernel32.is_null() {
        return Err(Error::GetModuleHandle(GetLastError()));
    }

    let load_library = GetProcAddress(kernel32, "LoadLibraryA\0".as_ptr() as _);
    if load_library.is_null() {
        return Err(Error::GetProcAddress(GetLastError()));
    }

    let h_thread = CreateRemoteThread(
        h_process,
        0 as _,
        0,
        Some(transmute(load_library)),
        buf as _,
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

    Ok(())
}
