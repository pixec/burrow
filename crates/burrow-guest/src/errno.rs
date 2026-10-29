//! Errors as the POSIX errno an SDK raises.
//!
//! `FsError` carries an errno name and its Linux number, because that is what
//! the SDKs map onto each language's own exceptions (`ENOENT` is Python's
//! `FileNotFoundError` and Node's `code: 'ENOENT'`). Windows errors map onto
//! errnos following libuv's mapping, which is what Node on Windows already
//! reports, so a program that handles Node's errors there handles these.
//! macOS has errnos of its own, numbered differently past 34, and gives each
//! Linux's number by name.

// Built off Windows only for its tests and, on macOS, `linux_number`.
#![cfg_attr(not(windows), allow(dead_code))]

/// An errno, by its Linux number. Named as the errno is, since the name is
/// what goes on the wire.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    EIO = 5,
    EBADF = 9,
    ENOMEM = 12,
    EACCES = 13,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    EMFILE = 24,
    EFBIG = 27,
    ENOSPC = 28,
    EROFS = 30,
    EPIPE = 32,
    ENAMETOOLONG = 36,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
    ENOTSUP = 95,
}

impl Errno {
    pub fn name(self) -> String {
        format!("{self:?}")
    }

    pub fn number(self) -> i32 {
        self as i32
    }
}

/// Win32 error codes, as `GetLastError` and `RtlNtStatusToDosError` return
/// them, and the errno each is.
pub const TABLE: &[(u32, Errno)] = &[
    (1, Errno::EISDIR),         // ERROR_INVALID_FUNCTION: a read on a directory handle
    (2, Errno::ENOENT),         // ERROR_FILE_NOT_FOUND
    (3, Errno::ENOENT),         // ERROR_PATH_NOT_FOUND
    (4, Errno::EMFILE),         // ERROR_TOO_MANY_OPEN_FILES
    (5, Errno::EACCES),         // ERROR_ACCESS_DENIED
    (6, Errno::EBADF),          // ERROR_INVALID_HANDLE
    (8, Errno::ENOMEM),         // ERROR_NOT_ENOUGH_MEMORY
    (14, Errno::ENOMEM),        // ERROR_OUTOFMEMORY
    (15, Errno::ENOENT),        // ERROR_INVALID_DRIVE
    (17, Errno::EXDEV),         // ERROR_NOT_SAME_DEVICE
    (19, Errno::EROFS),         // ERROR_WRITE_PROTECT
    (32, Errno::EBUSY),         // ERROR_SHARING_VIOLATION
    (33, Errno::EBUSY),         // ERROR_LOCK_VIOLATION
    (39, Errno::ENOSPC),        // ERROR_HANDLE_DISK_FULL
    (50, Errno::ENOTSUP),       // ERROR_NOT_SUPPORTED
    (53, Errno::ENOENT),        // ERROR_BAD_NETPATH
    (80, Errno::EEXIST),        // ERROR_FILE_EXISTS
    (87, Errno::EINVAL),        // ERROR_INVALID_PARAMETER
    (109, Errno::EPIPE),        // ERROR_BROKEN_PIPE
    (112, Errno::ENOSPC),       // ERROR_DISK_FULL
    (120, Errno::ENOSYS),       // ERROR_CALL_NOT_IMPLEMENTED
    (123, Errno::ENOENT),       // ERROR_INVALID_NAME
    (131, Errno::EINVAL),       // ERROR_NEGATIVE_SEEK
    (145, Errno::ENOTEMPTY),    // ERROR_DIR_NOT_EMPTY
    (161, Errno::ENOENT),       // ERROR_BAD_PATHNAME
    (183, Errno::EEXIST),       // ERROR_ALREADY_EXISTS
    (206, Errno::ENAMETOOLONG), // ERROR_FILENAME_EXCED_RANGE
    (223, Errno::EFBIG),        // ERROR_FILE_TOO_LARGE
    (267, Errno::ENOTDIR),      // ERROR_DIRECTORY
    // ERROR_DELETE_PENDING: the name is on its way out and can no longer be
    // opened, which is what POSIX calls gone.
    (303, Errno::ENOENT),
    (740, Errno::EACCES),  // ERROR_ELEVATION_REQUIRED
    (1117, Errno::EIO),    // ERROR_IO_DEVICE
    (1314, Errno::EPERM),  // ERROR_PRIVILEGE_NOT_HELD
    (1920, Errno::EACCES), // ERROR_CANT_ACCESS_FILE
    (1921, Errno::ELOOP),  // ERROR_CANT_RESOLVE_FILENAME
    (4390, Errno::EINVAL), // ERROR_NOT_A_REPARSE_POINT: readlink of a non-link
];

/// Linux's errnos by name, every one a POSIX system shares with it. Names are
/// what a macOS errno is matched on; the two systems agree on them, not on
/// the numbers.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const LINUX: &[(&str, i32)] = &[
    ("EPERM", 1),
    ("ENOENT", 2),
    ("ESRCH", 3),
    ("EINTR", 4),
    ("EIO", 5),
    ("ENXIO", 6),
    ("E2BIG", 7),
    ("ENOEXEC", 8),
    ("EBADF", 9),
    ("ECHILD", 10),
    ("EAGAIN", 11),
    ("ENOMEM", 12),
    ("EACCES", 13),
    ("EFAULT", 14),
    ("ENOTBLK", 15),
    ("EBUSY", 16),
    ("EEXIST", 17),
    ("EXDEV", 18),
    ("ENODEV", 19),
    ("ENOTDIR", 20),
    ("EISDIR", 21),
    ("EINVAL", 22),
    ("ENFILE", 23),
    ("EMFILE", 24),
    ("ENOTTY", 25),
    ("ETXTBSY", 26),
    ("EFBIG", 27),
    ("ENOSPC", 28),
    ("ESPIPE", 29),
    ("EROFS", 30),
    ("EMLINK", 31),
    ("EPIPE", 32),
    ("EDOM", 33),
    ("ERANGE", 34),
    ("EDEADLK", 35),
    ("ENAMETOOLONG", 36),
    ("ENOLCK", 37),
    ("ENOSYS", 38),
    ("ENOTEMPTY", 39),
    ("ELOOP", 40),
    ("ENOMSG", 42),
    ("EIDRM", 43),
    ("ENOSTR", 60),
    ("ENODATA", 61),
    ("ETIME", 62),
    ("ENOSR", 63),
    ("EREMOTE", 66),
    ("ENOLINK", 67),
    ("EPROTO", 71),
    ("EMULTIHOP", 72),
    ("EBADMSG", 74),
    ("EOVERFLOW", 75),
    ("EILSEQ", 84),
    ("EUSERS", 87),
    ("ENOTSOCK", 88),
    ("EDESTADDRREQ", 89),
    ("EMSGSIZE", 90),
    ("EPROTOTYPE", 91),
    ("ENOPROTOOPT", 92),
    ("EPROTONOSUPPORT", 93),
    ("ESOCKTNOSUPPORT", 94),
    ("ENOTSUP", 95),
    ("EOPNOTSUPP", 95),
    ("EPFNOSUPPORT", 96),
    ("EAFNOSUPPORT", 97),
    ("EADDRINUSE", 98),
    ("EADDRNOTAVAIL", 99),
    ("ENETDOWN", 100),
    ("ENETUNREACH", 101),
    ("ENETRESET", 102),
    ("ECONNABORTED", 103),
    ("ECONNRESET", 104),
    ("ENOBUFS", 105),
    ("EISCONN", 106),
    ("ENOTCONN", 107),
    ("ESHUTDOWN", 108),
    ("ETOOMANYREFS", 109),
    ("ETIMEDOUT", 110),
    ("ECONNREFUSED", 111),
    ("EHOSTDOWN", 112),
    ("EHOSTUNREACH", 113),
    ("EALREADY", 114),
    ("EINPROGRESS", 115),
    ("ESTALE", 116),
    ("EDQUOT", 122),
    ("ECANCELED", 125),
    ("EOWNERDEAD", 130),
    ("ENOTRECOVERABLE", 131),
];

/// Linux's number for the errno called `name`, if Linux has one.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn linux_number(name: &str) -> Option<i32> {
    LINUX
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, number)| *number)
}

/// The errno for a Win32 error; `EIO` for anything the table does not know.
pub fn from_win32(code: u32) -> Errno {
    TABLE
        .iter()
        .find(|(win32, _)| *win32 == code)
        .map_or(Errno::EIO, |(_, errno)| *errno)
}

/// The errno for an `io::Error` the standard library produced on Windows,
/// where `raw_os_error` is the Win32 code.
pub fn from_io(err: &std::io::Error) -> Errno {
    err.raw_os_error()
        .map_or(Errno::EIO, |code| from_win32(code as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ones the SDKs branch on, by the name they raise.
    #[test]
    fn the_common_errors_map_to_their_posix_names() {
        let cases = [
            (2, "ENOENT", 2),
            (3, "ENOENT", 2),
            (5, "EACCES", 13),
            (80, "EEXIST", 17),
            (183, "EEXIST", 17),
            (145, "ENOTEMPTY", 39),
            (267, "ENOTDIR", 20),
            (17, "EXDEV", 18),
            (112, "ENOSPC", 28),
            (6, "EBADF", 9),
            (87, "EINVAL", 22),
            (32, "EBUSY", 16),
            (1314, "EPERM", 1),
        ];
        for (win32, name, number) in cases {
            let errno = from_win32(win32);
            assert_eq!(
                (errno.name().as_str(), errno.number()),
                (name, number),
                "{win32}"
            );
        }
    }

    #[test]
    fn an_unknown_error_is_eio() {
        assert_eq!(from_win32(999_999), Errno::EIO);
        assert_eq!(from_io(&std::io::Error::other("x")), Errno::EIO);
    }

    #[test]
    fn linux_numbers_go_by_name() {
        assert_eq!(linux_number("ELOOP"), Some(40));
        assert_eq!(linux_number("ENOTEMPTY"), Some(39));
        assert_eq!(linux_number("EAGAIN"), Some(11));
        assert_eq!(linux_number("EFTYPE"), None);
        for errno in [
            Errno::ENOENT,
            Errno::ELOOP,
            Errno::ENOTSUP,
            Errno::ENAMETOOLONG,
        ] {
            assert_eq!(linux_number(&errno.name()), Some(errno.number()));
        }
    }

    /// The errnos macOS numbers differently from Linux are known by name.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_errnos_have_linux_numbers() {
        use nix::errno::Errno as Native;
        for errno in [
            Native::EAGAIN,
            Native::ELOOP,
            Native::ENAMETOOLONG,
            Native::ENOTEMPTY,
            Native::EDQUOT,
            Native::ENOTSUP,
            Native::EOPNOTSUPP,
            Native::ENOSYS,
            Native::EOVERFLOW,
            Native::EILSEQ,
        ] {
            assert!(linux_number(&format!("{errno:?}")).is_some(), "{errno:?}");
        }
    }

    #[test]
    fn every_code_is_listed_once() {
        let mut codes: Vec<u32> = TABLE.iter().map(|(code, _)| *code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), TABLE.len());
    }
}
