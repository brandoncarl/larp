use crate::registry::{ClientIdentity, Registry};

#[cfg(target_os = "macos")]
mod mac {
    use super::{ClientIdentity, Registry};
    use std::ffi::{c_char, c_int, c_void, CStr, CString};
    use std::os::unix::ffi::OsStrExt;

    type Cf = *const c_void;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: Cf);
        fn CFURLCreateFromFileSystemRepresentation(
            allocator: Cf,
            bytes: *const u8,
            length: isize,
            is_directory: u8,
        ) -> Cf;
        fn CFNumberCreate(allocator: Cf, kind: isize, value: *const c_void) -> Cf;
        fn CFDictionaryCreateMutable(
            allocator: Cf,
            capacity: isize,
            keys: *const c_void,
            values: *const c_void,
        ) -> *mut c_void;
        fn CFDictionarySetValue(dictionary: *mut c_void, key: Cf, value: Cf);
        fn CFDictionaryGetValue(dictionary: Cf, key: Cf) -> Cf;
        fn CFStringCreateWithCString(allocator: Cf, value: *const c_char, encoding: u32) -> Cf;
        fn CFStringGetLength(value: Cf) -> isize;
        fn CFStringGetCString(value: Cf, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecGuestAttributePid: Cf;
        static kSecCodeInfoCertificates: Cf;
        fn SecStaticCodeCreateWithPath(path: Cf, flags: u32, code: *mut Cf) -> c_int;
        fn SecStaticCodeCheckValidity(code: Cf, flags: u32, requirement: Cf) -> c_int;
        fn SecCodeCopySigningInformation(code: Cf, flags: u32, information: *mut Cf) -> c_int;
        fn SecCodeCopyDesignatedRequirement(code: Cf, flags: u32, requirement: *mut Cf) -> c_int;
        fn SecRequirementCopyString(requirement: Cf, flags: u32, text: *mut Cf) -> c_int;
        fn SecRequirementCreateWithString(text: Cf, flags: u32, requirement: *mut Cf) -> c_int;
        fn SecCodeCopyGuestWithAttributes(
            host: Cf,
            attributes: Cf,
            flags: u32,
            guest: *mut Cf,
        ) -> c_int;
        fn SecCodeCheckValidity(code: Cf, flags: u32, requirement: Cf) -> c_int;
    }

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            size: c_int,
        ) -> c_int;
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, size: u32) -> c_int;
    }

    struct Owned(Cf);
    impl Owned {
        fn new(value: Cf) -> Result<Self, String> {
            if value.is_null() {
                Err("macOS code identity lookup failed".into())
            } else {
                Ok(Self(value))
            }
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) };
        }
    }

    const UTF8: u32 = 0x0800_0100;
    const UNSIGNED: c_int = -67062;

    fn cf_string(value: &str) -> Result<Owned, String> {
        let c = CString::new(value).map_err(|_| "invalid code requirement")?;
        Owned::new(unsafe { CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), UTF8) })
    }

    fn string_from_cf(value: Cf) -> Result<String, String> {
        let chars = unsafe { CFStringGetLength(value) };
        if !(0..=4096).contains(&chars) {
            return Err("code requirement is too long".into());
        }
        let mut bytes = vec![0u8; chars as usize * 4 + 1];
        let ok = unsafe {
            CFStringGetCString(value, bytes.as_mut_ptr().cast(), bytes.len() as isize, UTF8)
        };
        if ok == 0 {
            return Err("could not decode code requirement".into());
        }
        CStr::from_bytes_until_nul(&bytes)
            .map_err(|_| String::from("invalid code requirement text"))?
            .to_str()
            .map(str::to_owned)
            .map_err(|_| "invalid code requirement UTF-8".into())
    }

    pub fn capture(path: &str) -> Result<ClientIdentity, String> {
        let bytes = std::path::Path::new(path).as_os_str().as_bytes();
        let url = Owned::new(unsafe {
            CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as isize,
                0,
            )
        })?;
        let mut code = std::ptr::null();
        let status = unsafe { SecStaticCodeCreateWithPath(url.0, 0, &mut code) };
        if status != 0 {
            return Err("could not inspect client code signature".into());
        }
        let code = Owned::new(code)?;
        match unsafe { SecStaticCodeCheckValidity(code.0, 0, std::ptr::null()) } {
            0 => {}
            UNSIGNED => return Ok(ClientIdentity::PathOnly),
            _ => return Err("client code signature is invalid".into()),
        }
        let mut info = std::ptr::null();
        if unsafe { SecCodeCopySigningInformation(code.0, 1 << 1, &mut info) } != 0 {
            return Err("could not inspect client signing information".into());
        }
        let info = Owned::new(info)?;
        if unsafe { CFDictionaryGetValue(info.0, kSecCodeInfoCertificates) }.is_null() {
            return Ok(ClientIdentity::PathOnly);
        }
        let mut requirement = std::ptr::null();
        if unsafe { SecCodeCopyDesignatedRequirement(code.0, 0, &mut requirement) } != 0 {
            return Err("could not capture client signing requirement".into());
        }
        let requirement = Owned::new(requirement)?;
        let mut text = std::ptr::null();
        if unsafe { SecRequirementCopyString(requirement.0, 0, &mut text) } != 0 {
            return Err("could not encode client signing requirement".into());
        }
        let text = Owned::new(text)?;
        Ok(ClientIdentity::Signed {
            requirement: string_from_cf(text.0)?,
        })
    }

    fn validate_running(pid: i32, requirement: &str) -> Result<(), String> {
        let number = Owned::new(unsafe {
            CFNumberCreate(std::ptr::null(), 3, (&pid as *const i32).cast())
        })?;
        let dictionary = Owned::new(unsafe {
            CFDictionaryCreateMutable(std::ptr::null(), 1, std::ptr::null(), std::ptr::null())
        })?;
        unsafe {
            CFDictionarySetValue(dictionary.0.cast_mut(), kSecGuestAttributePid, number.0);
        }
        let mut code = std::ptr::null();
        if unsafe { SecCodeCopyGuestWithAttributes(std::ptr::null(), dictionary.0, 0, &mut code) }
            != 0
        {
            return Err("running client code could not be located".into());
        }
        let code = Owned::new(code)?;
        let text = cf_string(requirement)?;
        let mut expected = std::ptr::null();
        if unsafe { SecRequirementCreateWithString(text.0, 0, &mut expected) } != 0 {
            return Err("registered signing requirement is invalid".into());
        }
        let expected = Owned::new(expected)?;
        if unsafe { SecCodeCheckValidity(code.0, 0, expected.0) } != 0 {
            return Err("running client does not satisfy its registered signature".into());
        }
        Ok(())
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        reserved: u32,
        comm: [u8; 16],
        name: [u8; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        tdev: u32,
        tpgid: u32,
        nice: i32,
        start_sec: u64,
        start_usec: u64,
    }

    #[derive(PartialEq, Eq)]
    struct Snapshot {
        pid: i32,
        ppid: i32,
        uid: u32,
        start_sec: u64,
        start_usec: u64,
        path: String,
    }

    fn snapshot(pid: i32) -> Result<Snapshot, String> {
        let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
        let size = std::mem::size_of::<ProcBsdInfo>();
        let read = unsafe { proc_pidinfo(pid, 3, 0, info.as_mut_ptr().cast(), size as i32) };
        if read != size as i32 {
            return Err("client process exited or changed during verification".into());
        }
        let info = unsafe { info.assume_init() };
        if info.pid != pid as u32 {
            return Err("client PID changed during verification".into());
        }
        let mut path = [0u8; 4096];
        let len = unsafe { proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if len <= 0 {
            return Err("could not resolve running client path".into());
        }
        let path = CStr::from_bytes_until_nul(&path).map_err(|_| "invalid running client path")?;
        let path = path
            .to_str()
            .map_err(|_| "running client path is not UTF-8")?
            .to_owned();
        Ok(Snapshot {
            pid,
            ppid: info.ppid as i32,
            uid: info.uid,
            start_sec: info.start_sec,
            start_usec: info.start_usec,
            path,
        })
    }

    pub fn identify(
        bridge_pid: i32,
        uid: u32,
        registry: &Registry,
    ) -> Result<(String, &'static str, String), String> {
        let bridge = snapshot(bridge_pid)?;
        if bridge.uid != uid || bridge.ppid <= 0 {
            return Err("bridge process identity mismatch".into());
        }
        let parent = snapshot(bridge.ppid)?;
        if parent.uid != uid {
            return Err("client process user mismatch".into());
        }
        let (name, client) = registry
            .client_for_process(&parent.path)
            .ok_or("bridge parent process is not a registered client")?;
        if let ClientIdentity::Signed { requirement } = &client.identity {
            validate_running(parent.pid, requirement)?;
        }
        if snapshot(bridge_pid)? != bridge || snapshot(parent.pid)? != parent {
            return Err("client process changed during verification".into());
        }
        Ok((name.to_owned(), client.identity.label(), parent.path))
    }

    pub fn unregistered_process(bridge_pid: i32, uid: u32, registry: &Registry) -> Option<String> {
        let bridge = snapshot(bridge_pid).ok()?;
        if bridge.uid != uid || bridge.ppid <= 0 {
            return None;
        }
        let parent = snapshot(bridge.ppid).ok()?;
        if parent.uid != uid
            || registry
                .clients
                .values()
                .any(|client| crate::registry::process_matches(&client.process, &parent.path))
        {
            return None;
        }
        if snapshot(bridge_pid).ok()? != bridge || snapshot(parent.pid).ok()? != parent {
            return None;
        }
        Some(parent.path)
    }

    #[cfg(test)]
    mod tests {
        use super::{capture, identify, snapshot, unregistered_process, validate_running};
        use crate::registry::{Client, ClientIdentity, Registry};
        use std::collections::BTreeSet;

        #[test]
        fn captures_signed_requirement_and_rejects_other_binary() {
            let ClientIdentity::Signed { requirement } = capture("/bin/sleep").unwrap() else {
                panic!("system sleep should be signed");
            };
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("3")
                .spawn()
                .unwrap();
            let pid = child.id() as i32;
            assert!(validate_running(pid, &requirement).is_ok());
            let ClientIdentity::Signed { requirement: wrong } = capture("/bin/echo").unwrap()
            else {
                panic!("system echo should be signed");
            };
            assert!(validate_running(pid, &wrong).is_err());
            assert_eq!(snapshot(pid).unwrap().pid, pid);
            let _ = child.kill();
            let _ = child.wait();
            assert!(snapshot(pid).is_err());
        }

        #[test]
        fn unsigned_script_is_explicitly_path_only() {
            let path =
                std::env::temp_dir().join(format!("larp-unsigned-{}.sh", std::process::id()));
            std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
            let identity = capture(path.to_str().unwrap()).unwrap();
            assert!(matches!(identity, ClientIdentity::PathOnly));
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn unknown_parent_and_exited_bridge_fail_closed() {
            let parent = snapshot(std::process::id() as i32).unwrap();
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("3")
                .spawn()
                .unwrap();
            let pid = child.id() as i32;
            let uid = unsafe { libc::geteuid() };
            assert!(identify(pid, uid, &Registry::default()).is_err());
            assert_eq!(
                unregistered_process(pid, uid, &Registry::default()),
                Some(parent.path.clone())
            );
            let mut registry = Registry::default();
            registry.clients.insert(
                "test".into(),
                Client {
                    process: parent.path.clone(),
                    identity: ClientIdentity::PathOnly,
                    commands: BTreeSet::new(),
                    secrets: BTreeSet::new(),
                    exec: BTreeSet::new(),
                },
            );
            assert_eq!(identify(pid, uid, &registry).unwrap().1, "path-only");
            assert_eq!(unregistered_process(pid, uid, &registry), None);
            registry.clients.insert(
                "overlap".into(),
                Client {
                    process: parent.path.clone(),
                    identity: ClientIdentity::PathOnly,
                    commands: BTreeSet::new(),
                    secrets: BTreeSet::new(),
                    exec: BTreeSet::new(),
                },
            );
            assert!(identify(pid, uid, &registry).is_err());
            // Ambiguous registrations must not become a new registration candidate.
            assert_eq!(unregistered_process(pid, uid, &registry), None);
            let _ = child.kill();
            let _ = child.wait();
            assert!(identify(pid, uid, &registry).is_err());
            assert_eq!(unregistered_process(pid, uid, &Registry::default()), None);
        }
    }
}

#[cfg(target_os = "macos")]
pub use mac::{capture, identify, unregistered_process};

#[cfg(not(target_os = "macos"))]
pub fn capture(_: &str) -> Result<ClientIdentity, String> {
    Ok(ClientIdentity::PathOnly)
}

#[cfg(not(target_os = "macos"))]
pub fn identify(_: i32, _: u32, _: &Registry) -> Result<(String, &'static str, String), String> {
    Err("verified caller identity currently requires macOS".into())
}

#[cfg(not(target_os = "macos"))]
pub fn unregistered_process(_: i32, _: u32, _: &Registry) -> Option<String> {
    None
}
