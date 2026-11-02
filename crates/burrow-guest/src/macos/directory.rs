//! Account lookups straight from Open Directory.
//!
//! libc's getpwnam and getgrnam answer from libinfo's cache inside the
//! calling process, which can keep an account deleted with `dscl` or
//! `sysadminctl` found for as long as the agent runs. Here each lookup is an
//! Open Directory query on the search node, the node libinfo itself reads,
//! so it sees the directory as it is now.

use std::ffi::c_void;

type CFTypeRef = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRetain(object: CFTypeRef) -> CFTypeRef;
    fn CFRelease(object: CFTypeRef);
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: bool,
    ) -> CFTypeRef;
    fn CFStringGetTypeID() -> usize;
    fn CFGetTypeID(object: CFTypeRef) -> usize;
    fn CFStringGetLength(string: CFTypeRef) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(string: CFTypeRef, buffer: *mut u8, size: isize, encoding: u32) -> bool;
    fn CFArrayGetCount(array: CFTypeRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFTypeRef, index: isize) -> CFTypeRef;
}

#[link(name = "OpenDirectory", kind = "framework")]
unsafe extern "C" {
    static kODSessionDefault: CFTypeRef;
    static kODRecordTypeUsers: CFTypeRef;
    static kODRecordTypeGroups: CFTypeRef;
    static kODAttributeTypeRecordName: CFTypeRef;
    static kODAttributeTypeUniqueID: CFTypeRef;
    static kODAttributeTypePrimaryGroupID: CFTypeRef;
    static kODAttributeTypeNFSHomeDirectory: CFTypeRef;
    static kODAttributeTypeUserShell: CFTypeRef;
    static kODAttributeTypeStandardOnly: CFTypeRef;
    fn ODNodeCreateWithNodeType(
        allocator: CFTypeRef,
        session: CFTypeRef,
        node_type: u32,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn ODQueryCreateWithNode(
        allocator: CFTypeRef,
        node: CFTypeRef,
        record_type: CFTypeRef,
        attribute: CFTypeRef,
        match_type: u32,
        value: CFTypeRef,
        returned: CFTypeRef,
        max_results: isize,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn ODQueryCopyResults(query: CFTypeRef, partial: bool, error: *mut CFTypeRef) -> CFTypeRef;
    fn ODRecordCopyValues(
        record: CFTypeRef,
        attribute: CFTypeRef,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
}

const UTF8: u32 = 0x0800_0100;
const NODE_TYPE_AUTHENTICATION: u32 = 0x2201;
const MATCH_EQUAL_TO: u32 = 0x2001;

/// A CF object this module created and releases.
struct Owned(CFTypeRef);

impl Owned {
    fn new(object: CFTypeRef) -> Option<Self> {
        (!object.is_null()).then_some(Self(object))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: a non-null object this module holds one reference to.
        unsafe { CFRelease(self.0) }
    }
}

fn cf_string(text: &str) -> Option<Owned> {
    // SAFETY: the bytes are valid for their length for the call.
    Owned::new(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            text.as_ptr(),
            text.len() as isize,
            UTF8,
            false,
        )
    })
}

fn rust_string(string: CFTypeRef) -> Option<String> {
    // SAFETY: `string` is a live CF object; the buffer is sized for the
    // longest encoding of its length plus the NUL.
    unsafe {
        if CFGetTypeID(string) != CFStringGetTypeID() {
            return None;
        }
        let size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(string), UTF8) + 1;
        let mut buf = vec![0u8; size as usize];
        if !CFStringGetCString(string, buf.as_mut_ptr(), size, UTF8) {
            return None;
        }
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        buf.truncate(end);
        String::from_utf8(buf).ok()
    }
}

/// One record's attributes, by Open Directory's names.
pub struct Record(Owned);

impl Record {
    fn values(&self, attribute: CFTypeRef) -> Vec<String> {
        // SAFETY: the record is live; the array is released by `Owned`.
        let Some(values) =
            Owned::new(unsafe { ODRecordCopyValues(self.0.0, attribute, std::ptr::null_mut()) })
        else {
            return Vec::new();
        };
        // SAFETY: indices below the array's count.
        (0..unsafe { CFArrayGetCount(values.0) })
            .filter_map(|i| rust_string(unsafe { CFArrayGetValueAtIndex(values.0, i) }))
            .collect()
    }

    fn first(&self, attribute: CFTypeRef) -> Option<String> {
        self.values(attribute).into_iter().next()
    }

    fn id(&self, attribute: CFTypeRef) -> Option<u32> {
        self.first(attribute).as_deref().and_then(parse_id)
    }
}

/// Directory ids are written signed: `nobody` is -2, which the kernel reads
/// as 4294967294.
fn parse_id(text: &str) -> Option<u32> {
    text.parse::<u32>()
        .ok()
        .or_else(|| text.parse::<i32>().ok().map(|id| id as u32))
}

fn id_text(id: u32) -> String {
    if id > i32::MAX as u32 {
        (id as i32).to_string()
    } else {
        id.to_string()
    }
}

/// The first record of `record_type` whose `attribute` is `value`.
fn find(record_type: CFTypeRef, attribute: CFTypeRef, value: &str) -> Option<Record> {
    let value = cf_string(value)?;
    // SAFETY: every object passed is live for its call; what comes back is
    // released by `Owned`, and the record is retained by `Owned` past the
    // results array it came from.
    unsafe {
        let node = Owned::new(ODNodeCreateWithNodeType(
            std::ptr::null(),
            kODSessionDefault,
            NODE_TYPE_AUTHENTICATION,
            std::ptr::null_mut(),
        ))?;
        let query = Owned::new(ODQueryCreateWithNode(
            std::ptr::null(),
            node.0,
            record_type,
            attribute,
            MATCH_EQUAL_TO,
            value.0,
            kODAttributeTypeStandardOnly,
            1,
            std::ptr::null_mut(),
        ))?;
        let results = Owned::new(ODQueryCopyResults(query.0, false, std::ptr::null_mut()))?;
        if CFArrayGetCount(results.0) < 1 {
            return None;
        }
        let record = CFArrayGetValueAtIndex(results.0, 0);
        Some(Record(Owned(CFRetain(record))))
    }
}

/// A user, as getpwnam would report them.
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

fn user(record: Record) -> Option<User> {
    // SAFETY: reading framework constants.
    unsafe {
        Some(User {
            name: record.first(kODAttributeTypeRecordName)?,
            uid: record.id(kODAttributeTypeUniqueID)?,
            gid: record.id(kODAttributeTypePrimaryGroupID)?,
            home: record
                .first(kODAttributeTypeNFSHomeDirectory)
                .unwrap_or_default(),
            shell: record.first(kODAttributeTypeUserShell).unwrap_or_default(),
        })
    }
}

pub fn user_named(name: &str) -> Option<User> {
    // SAFETY: reading framework constants.
    find(
        unsafe { kODRecordTypeUsers },
        unsafe { kODAttributeTypeRecordName },
        name,
    )
    .and_then(user)
}

pub fn user_with_id(uid: u32) -> Option<User> {
    // SAFETY: reading framework constants.
    find(
        unsafe { kODRecordTypeUsers },
        unsafe { kODAttributeTypeUniqueID },
        &id_text(uid),
    )
    .and_then(user)
}

/// A group's id by name.
pub fn group_named(name: &str) -> Option<u32> {
    // SAFETY: reading framework constants.
    find(
        unsafe { kODRecordTypeGroups },
        unsafe { kODAttributeTypeRecordName },
        name,
    )?
    .id(unsafe { kODAttributeTypePrimaryGroupID })
}

pub fn group_with_id(gid: u32) -> bool {
    // SAFETY: reading framework constants.
    find(
        unsafe { kODRecordTypeGroups },
        unsafe { kODAttributeTypePrimaryGroupID },
        &id_text(gid),
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_read_as_the_kernel_reads_them() {
        assert_eq!(parse_id("501"), Some(501));
        assert_eq!(parse_id("-2"), Some(4_294_967_294));
        assert_eq!(parse_id("x"), None);
        assert_eq!(id_text(4_294_967_294), "-2");
        assert_eq!(id_text(501), "501");
    }

    /// The directory agrees with libc about the accounts every Mac has.
    #[test]
    fn system_accounts_match_libc() {
        let root = user_named("root").unwrap();
        assert_eq!(
            (root.uid, root.gid, root.home.as_str()),
            (0, 0, "/var/root")
        );
        assert_eq!(user_with_id(0).unwrap().name, "root");
        let nobody = user_named("nobody").unwrap();
        assert_eq!(nobody.uid, 4_294_967_294);
        assert_eq!(user_with_id(nobody.uid).unwrap().name, "nobody");
        assert_eq!(group_named("staff"), Some(20));
        assert!(group_with_id(20));
        assert!(user_named("no-such-user").is_none());
        assert!(group_named("no-such-group").is_none());
        assert!(!group_with_id(59_999));
    }
}
