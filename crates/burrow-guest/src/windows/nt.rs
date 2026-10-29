//! Acting on files through handles.
//!
//! The Linux agent checks a path's scope on the descriptor it then acts
//! through, so nothing renamed or relinked in between can redirect the call.
//! Win32 file APIs mostly take paths, which would reopen the gap; these are
//! the handle-based ones: `NtCreateFile` relative to a directory handle for
//! opening and creating a name in a checked directory, and
//! `SetFileInformationByHandle` / `NtSetInformationFile` for deleting,
//! renaming and linking the object a handle holds.

use std::fs::File;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_LINK_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileLinkInformation, NtCreateFile,
    NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{HANDLE, OBJ_CASE_INSENSITIVE, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FULL_DIR_INFO, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileBasicInfo,
    FileDispositionInfoEx, FileFullDirectoryInfo, FileFullDirectoryRestartInfo, FileRenameInfoEx,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};

use crate::windows::win;

pub const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const FILE_READ_ATTRIBUTES: u32 = 0x80;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
pub const FILE_LIST_DIRECTORY: u32 = 0x1;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;

/// `NtCreateFile` dispositions and options, as `ntifs.h` names them.
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_DIRECTORY_FILE: u32 = 0x1;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
pub const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
pub const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x4000;

const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
const SYMLINK_FLAG_RELATIVE: u32 = 1;
const ERROR_NO_MORE_FILES: i32 = 18;
const ERROR_INVALID_PARAMETER: i32 = 87;
const ERROR_NOT_SUPPORTED: i32 = 50;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;

/// Opens a mapped path through Win32. Directories open too, as they do with
/// `open(2)`; `is_nofollow` opens a final symlink as itself. Whether
/// something was already there comes back with it, for the dispositions
/// that create.
pub fn open_path(
    path: &str,
    access: u32,
    disposition: u32,
    is_nofollow: bool,
) -> std::io::Result<(File, bool)> {
    let long = win::wide(&crate::paths::windows::long(path));
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
    if is_nofollow {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    // SAFETY: `long` is NUL-terminated; the handle is owned below.
    let handle = unsafe {
        CreateFileW(
            long.as_ptr(),
            access,
            SHARE_ALL,
            std::ptr::null(),
            disposition,
            flags,
            std::ptr::null_mut(),
        )
    };
    // Read at once: ERROR_ALREADY_EXISTS on success is how CreateFileW says
    // an OPEN_ALWAYS found the file, and the next call may overwrite it.
    let existed = win::last_error() == 183;
    win::owned(handle).map(|handle| (File::from(handle), existed))
}

fn status_error(status: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(win::nt_error(status) as i32)
}

/// Opens or creates `name`, one component, inside the directory `dir`
/// holds. Whether it was created comes back with it.
///
/// Nothing in `name` is resolved but the name itself: a separator or `..`
/// is refused, so the result is an entry of `dir` and nothing else.
pub fn open_at(
    dir: &File,
    name: &str,
    access: u32,
    disposition: u32,
    options: u32,
    attributes: u32,
) -> std::io::Result<(File, bool)> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['\\', '/']) {
        return Err(std::io::Error::from_raw_os_error(123));
    }
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let object = UNICODE_STRING {
        Length: (wide.len() * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir.as_raw_handle(),
        ObjectName: &object,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer is to a live local.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attrs,
            &mut io,
            std::ptr::null(),
            attributes,
            SHARE_ALL,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // EEXIST for a create that found something, which is what the
        // generic mapping also says; spelt out because callers branch on it.
        if status == STATUS_OBJECT_NAME_COLLISION {
            return Err(std::io::Error::from_raw_os_error(183));
        }
        return Err(status_error(status));
    }
    // FILE_CREATED is 2 in the Information an NtCreateFile reports.
    let created = io.Information == 2;
    // SAFETY: a fresh handle nothing else owns.
    Ok((unsafe { File::from_raw_handle(handle) }, created))
}

/// The path the handle is open on, in drive form.
pub fn final_path(file: &File) -> std::io::Result<String> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `buf` has room for the length passed.
        let len = unsafe {
            GetFinalPathNameByHandleW(file.as_raw_handle(), buf.as_mut_ptr(), buf.len() as u32, 0)
        };
        if len == 0 {
            return Err(win::last_io_error());
        }
        if (len as usize) < buf.len() {
            return Ok(crate::paths::windows::from_final(
                &String::from_utf16_lossy(&buf[..len as usize]),
            ));
        }
        buf.resize(len as usize + 1, 0);
    }
}

/// What a handle's object is, as far as stat needs it.
pub struct Info {
    pub attributes: u32,
    pub reparse_tag: u32,
    pub size: u64,
    pub allocated: u64,
    pub nlink: u32,
    pub volume: u32,
    pub index: u64,
    pub created: i64,
    pub accessed: i64,
    pub written: i64,
    pub changed: i64,
}

impl Info {
    pub fn is_dir(&self) -> bool {
        self.attributes & crate::windows::mode::FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub fn is_link(&self) -> bool {
        crate::windows::mode::is_link(self.attributes, self.reparse_tag)
    }

    /// Whether two handles hold the same object.
    pub fn is_same(&self, other: &Info) -> bool {
        (self.volume, self.index) == (other.volume, other.index)
    }
}

fn get_ex<T>(file: &File, class: i32) -> std::io::Result<T> {
    let mut out: T = unsafe { std::mem::zeroed() };
    // SAFETY: `out` is the size passed and the type the class writes.
    win::check(unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&raw mut out).cast(),
            std::mem::size_of::<T>() as u32,
        )
    })?;
    Ok(out)
}

pub fn info(file: &File) -> std::io::Result<Info> {
    use windows_sys::Win32::Storage::FileSystem::{FileAttributeTagInfo, FileStandardInfo};
    let mut by: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `by` is written by the call.
    win::check(unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut by) })?;
    let basic: FILE_BASIC_INFO = get_ex(file, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = get_ex(file, FileStandardInfo)?;
    let tag: FILE_ATTRIBUTE_TAG_INFO = get_ex(file, FileAttributeTagInfo)?;
    Ok(Info {
        attributes: by.dwFileAttributes,
        reparse_tag: tag.ReparseTag,
        size: standard.EndOfFile as u64,
        allocated: standard.AllocationSize as u64,
        nlink: by.nNumberOfLinks,
        volume: by.dwVolumeSerialNumber,
        index: (u64::from(by.nFileIndexHigh) << 32) | u64::from(by.nFileIndexLow),
        created: basic.CreationTime,
        accessed: basic.LastAccessTime,
        written: basic.LastWriteTime,
        changed: basic.ChangeTime,
    })
}

/// Sets times (FILETIMEs) and attributes through the handle; `None` leaves
/// one as it is, which FILE_BASIC_INFO spells as zero.
pub fn set_basic(
    file: &File,
    accessed: Option<i64>,
    written: Option<i64>,
    attributes: Option<u32>,
) -> std::io::Result<()> {
    let basic = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: accessed.unwrap_or(0),
        LastWriteTime: written.unwrap_or(0),
        ChangeTime: 0,
        // A value of 0 leaves attributes alone; NORMAL is what clearing all
        // of them is spelt as.
        FileAttributes: attributes.map_or(0, |a| if a == 0 { 0x80 } else { a }),
    };
    // SAFETY: `basic` is the structure the class reads.
    win::check(unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            (&raw const basic).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    })
}

/// One directory entry.
pub struct Entry {
    pub name: String,
    pub attributes: u32,
    /// The reparse tag, for an entry that is a reparse point.
    pub reparse_tag: u32,
    pub size: u64,
}

/// Lists the directory the handle holds, without `.` and `..`.
pub fn entries(dir: &File) -> std::io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut buf = vec![0u64; 8 * 1024];
    let mut class = FileFullDirectoryRestartInfo;
    loop {
        // SAFETY: `buf` is the size passed and 8-aligned, as the entries are.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.as_raw_handle(),
                class,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
            )
        };
        if ok == 0 {
            let err = win::last_io_error();
            if err.raw_os_error() == Some(ERROR_NO_MORE_FILES) {
                return Ok(out);
            }
            return Err(err);
        }
        class = FileFullDirectoryInfo;
        let base = buf.as_ptr().cast::<u8>();
        let mut offset = 0usize;
        loop {
            // SAFETY: the system wrote a chain of entries into `buf`, each at
            // the offset the one before names.
            let entry = unsafe { &*base.add(offset).cast::<FILE_FULL_DIR_INFO>() };
            let name = unsafe {
                std::slice::from_raw_parts(
                    entry.FileName.as_ptr(),
                    entry.FileNameLength as usize / 2,
                )
            };
            let name = String::from_utf16_lossy(name);
            if name != "." && name != ".." {
                out.push(Entry {
                    name,
                    attributes: entry.FileAttributes,
                    // For a reparse point the EA size field holds its tag.
                    reparse_tag: if entry.FileAttributes
                        & crate::windows::mode::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                    {
                        entry.EaSize
                    } else {
                        0
                    },
                    size: entry.EndOfFile as u64,
                });
            }
            if entry.NextEntryOffset == 0 {
                break;
            }
            offset += entry.NextEntryOffset as usize;
        }
    }
}

/// Deletes what the handle holds, which needs DELETE access. With POSIX
/// semantics where the volume has them: the name goes at once even while
/// another handle is open, as `unlink(2)` does, and a read-only file goes
/// too, as on Linux, where the mode is no bar to unlinking.
pub fn delete(file: &File) -> std::io::Result<()> {
    // DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE.
    let flags: u32 = 0x1 | 0x2 | 0x10;
    // SAFETY: a u32 is FILE_DISPOSITION_INFO_EX.
    let ex = win::check(unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&raw const flags).cast(),
            4,
        )
    });
    match ex {
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
            ) =>
        {
            use windows_sys::Win32::Storage::FileSystem::FileDispositionInfo;
            let delete: u8 = 1;
            // SAFETY: a BOOLEAN is FILE_DISPOSITION_INFO.
            win::check(unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    (&raw const delete).cast(),
                    1,
                )
            })
        }
        other => other,
    }
}

/// A FILE_RENAME_INFO or FILE_LINK_INFORMATION, which share a layout: a
/// flags word, a root directory, a length and the name.
fn name_block(root: &File, name: &str, flags: u32) -> (Vec<u64>, usize) {
    let wide: Vec<u16> = name.encode_utf16().collect();
    let head = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = head + wide.len() * 2 + 2;
    let mut block = vec![0u64; size.div_ceil(8)];
    let info = block.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the block is `size` bytes, aligned for the structure, with
    // room for the name after its head.
    unsafe {
        (*info).Anonymous.Flags = flags;
        (*info).RootDirectory = root.as_raw_handle();
        (*info).FileNameLength = (wide.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(wide.as_ptr(), (*info).FileName.as_mut_ptr(), wide.len());
    }
    (block, size)
}

/// Renames what `file` holds (opened with DELETE) to `name` in `to`,
/// replacing what is there, as rename(2) does.
pub fn rename(file: &File, to: &File, name: &str) -> std::io::Result<()> {
    // REPLACE_IF_EXISTS | POSIX_SEMANTICS.
    let (block, size) = name_block(to, name, 0x1 | 0x2);
    // SAFETY: the block is the structure the class reads.
    let ex = win::check(unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfoEx,
            block.as_ptr().cast(),
            size as u32,
        )
    });
    match ex {
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
            ) =>
        {
            use windows_sys::Win32::Storage::FileSystem::FileRenameInfo;
            let (block, size) = name_block(to, name, 1);
            // SAFETY: as above, with ReplaceIfExists in the flags word.
            win::check(unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileRenameInfo,
                    block.as_ptr().cast(),
                    size as u32,
                )
            })
        }
        other => other,
    }
}

/// Makes `name` in `to` another hard link to what `file` holds.
pub fn link(file: &File, to: &File, name: &str) -> std::io::Result<()> {
    debug_assert_eq!(
        std::mem::offset_of!(FILE_RENAME_INFO, FileName),
        std::mem::offset_of!(FILE_LINK_INFORMATION, FileName)
    );
    let (block, size) = name_block(to, name, 0);
    let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: the block is a FILE_LINK_INFORMATION of `size` bytes.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut io,
            block.as_ptr().cast(),
            size as u32,
            FileLinkInformation,
        )
    };
    if status < 0 {
        if status == STATUS_OBJECT_NAME_COLLISION {
            return Err(std::io::Error::from_raw_os_error(183));
        }
        return Err(status_error(status));
    }
    Ok(())
}

fn u16_at(buf: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([buf[at], buf[at + 1]]))
}

/// What a symlink or junction the handle holds (opened as itself) points at.
pub fn read_link(file: &File) -> std::io::Result<String> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut returned = 0u32;
    // SAFETY: `buf` is the size passed.
    win::check(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    })?;
    let tag = u32::from_le_bytes(buf[..4].try_into().expect("four bytes"));
    // The path buffer follows the header, which a symlink's flags word makes
    // four bytes longer than a junction's.
    let path_at = match tag {
        crate::windows::mode::IO_REPARSE_TAG_SYMLINK => 20,
        crate::windows::mode::IO_REPARSE_TAG_MOUNT_POINT => 16,
        _ => return Err(std::io::Error::from_raw_os_error(4390)),
    };
    let name = |offset: usize, len: usize| {
        let bytes = &buf[path_at + offset..path_at + offset + len];
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&wide)
    };
    let print = name(u16_at(&buf, 12), u16_at(&buf, 14));
    if !print.is_empty() {
        return Ok(print);
    }
    let substitute = name(u16_at(&buf, 8), u16_at(&buf, 10));
    Ok(substitute
        .strip_prefix("\\??\\")
        .map(str::to_string)
        .unwrap_or(substitute))
}

/// Makes the empty file or directory the handle holds a symlink to
/// `target`, stored as written when relative and in drive form when not.
pub fn set_symlink(file: &File, target: &str, absolute: Option<&str>) -> std::io::Result<()> {
    let (substitute, print, flags) = match absolute {
        Some(mapped) => (format!("\\??\\{mapped}"), mapped.to_string(), 0),
        None => {
            let relative = target.replace('/', "\\");
            (relative.clone(), relative, SYMLINK_FLAG_RELATIVE)
        }
    };
    let substitute: Vec<u16> = substitute.encode_utf16().collect();
    let print: Vec<u16> = print.encode_utf16().collect();
    let path_len = (substitute.len() + print.len()) * 2;
    let mut buf = Vec::with_capacity(20 + path_len);
    buf.extend(crate::windows::mode::IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    buf.extend(((12 + path_len) as u16).to_le_bytes());
    buf.extend(0u16.to_le_bytes());
    buf.extend(0u16.to_le_bytes());
    buf.extend(((substitute.len() * 2) as u16).to_le_bytes());
    buf.extend(((substitute.len() * 2) as u16).to_le_bytes());
    buf.extend(((print.len() * 2) as u16).to_le_bytes());
    buf.extend(flags.to_le_bytes());
    for c in substitute.iter().chain(&print) {
        buf.extend(c.to_le_bytes());
    }
    let mut returned = 0u32;
    // SAFETY: `buf` is the reparse buffer, sized as passed.
    win::check(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr().cast(),
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    })
}
