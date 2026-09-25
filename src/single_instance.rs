use std::error::Error;

/// Cross-platform single instance mechanism.
/// Ensures only one instance of the application runs at any time.
pub struct SingleInstance {
    #[cfg(target_os = "windows")]
    inner: windows::InstanceHandle,
    #[cfg(target_os = "linux")]
    inner: linux::InstanceHandle,
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    inner: fallback::InstanceHandle,
}

impl SingleInstance {
    /// Attempts to acquire a single instance lock for the given identifier.
    pub fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        #[cfg(target_os = "windows")]
        {
            let inner = windows::InstanceHandle::create(name)?;
            Ok(Self { inner })
        }
        #[cfg(target_os = "linux")]
        {
            let inner = linux::InstanceHandle::create(name)?;
            Ok(Self { inner })
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let inner = fallback::InstanceHandle::create(name)?;
            Ok(Self { inner })
        }
    }

    /// Returns `true` if this process is the single running instance.
    /// Returns `false` if another instance is already running.
    pub fn is_single(&self) -> bool {
        self.inner.is_single()
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::error::Error;
    use std::ffi::c_void;

    const ERROR_ALREADY_EXISTS: u32 = 183;
    const ERROR_ACCESS_DENIED: u32 = 5;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(
            lpMutexAttributes: *mut c_void,
            bInitialOwner: i32,
            lpName: *const u16,
        ) -> isize;
        fn GetLastError() -> u32;
        fn CloseHandle(hObject: isize) -> i32;
    }

    pub struct InstanceHandle {
        handle: isize,
        is_single: bool,
    }

    impl InstanceHandle {
        pub fn create(name: &str) -> Result<Self, Box<dyn Error>> {
            let sanitized_name = if name.starts_with("Local\\") || name.starts_with("Global\\") {
                name.to_string()
            } else {
                format!("Local\\{}", name)
            };

            let wide_name: Vec<u16> = sanitized_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let handle = CreateMutexW(std::ptr::null_mut(), 1, wide_name.as_ptr());
                if handle == 0 {
                    let err = GetLastError();
                    if err == ERROR_ACCESS_DENIED {
                        // The mutex already exists and is held with restricted permissions
                        return Ok(Self {
                            handle: 0,
                            is_single: false,
                        });
                    }
                    return Err(format!("CreateMutexW failed with code {}", err).into());
                }
                let err = GetLastError();
                let is_single = err != ERROR_ALREADY_EXISTS;
                Ok(Self { handle, is_single })
            }
        }

        pub fn is_single(&self) -> bool {
            self.is_single
        }
    }

    impl Drop for InstanceHandle {
        fn drop(&mut self) {
            if self.handle != 0 {
                unsafe {
                    CloseHandle(self.handle);
                }
                self.handle = 0;
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::io::ErrorKind;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    pub struct InstanceHandle {
        _listener: Option<UnixListener>,
        is_single: bool,
    }

    impl InstanceHandle {
        pub fn create(name: &str) -> Result<Self, Box<dyn Error>> {
            let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
            match UnixListener::bind_addr(&addr) {
                Ok(listener) => Ok(Self {
                    _listener: Some(listener),
                    is_single: true,
                }),
                Err(err) if err.kind() == ErrorKind::AddrInUse => Ok(Self {
                    _listener: None,
                    is_single: false,
                }),
                Err(err) => Err(err.into()),
            }
        }

        pub fn is_single(&self) -> bool {
            self.is_single
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
mod fallback {
    use std::error::Error;
    use std::fs::{self, File};
    use std::path::PathBuf;

    pub struct InstanceHandle {
        lock_path: PathBuf,
        _file: Option<File>,
        is_single: bool,
    }

    impl InstanceHandle {
        pub fn create(name: &str) -> Result<Self, Box<dyn Error>> {
            let lock_path = std::env::temp_dir().join(format!("{}.single_instance.lock", name));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(file) => Ok(Self {
                    lock_path,
                    _file: Some(file),
                    is_single: true,
                }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Self {
                    lock_path,
                    _file: None,
                    is_single: false,
                }),
                Err(e) => Err(e.into()),
            }
        }

        pub fn is_single(&self) -> bool {
            self.is_single
        }
    }

    impl Drop for InstanceHandle {
        fn drop(&mut self) {
            if self.is_single {
                let _ = fs::remove_file(&self.lock_path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_single_instance_acquisition_and_release() {
        let unique_name = format!("NoteVault_Test_{}", Uuid::new_v4());

        // First instance acquires lock
        let inst1 = SingleInstance::new(&unique_name).expect("First instance creation should succeed");
        assert!(inst1.is_single(), "First instance must be single");

        // Second instance with same name detects existing instance
        let inst2 = SingleInstance::new(&unique_name).expect("Second instance creation should succeed");
        assert!(!inst2.is_single(), "Second instance must detect already running instance");

        // Drop both instances so all handles are closed
        drop(inst2);
        drop(inst1);

        // Third instance should now succeed in becoming the single instance
        let inst3 = SingleInstance::new(&unique_name).expect("Third instance creation should succeed");
        assert!(inst3.is_single(), "Third instance must be single after previous dropped");
    }
}
