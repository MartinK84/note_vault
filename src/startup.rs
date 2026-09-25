use std::error::Error;

/// Registers or unregisters the application to launch at system startup.
/// On Windows, this updates `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
/// If `minimized` is true, `--minimized` is appended to the registered executable command.
pub fn set_launch_at_startup(enabled: bool, minimized: bool) -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        windows::set_launch_at_startup(enabled, minimized)
    }
    #[cfg(target_os = "linux")]
    {
        linux::set_launch_at_startup(enabled, minimized)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (enabled, minimized);
        Ok(())
    }
}

/// Checks whether the application is currently registered to launch at system startup.
pub fn is_launch_at_startup_registered() -> Result<bool, Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        windows::is_launch_at_startup_registered()
    }
    #[cfg(target_os = "linux")]
    {
        linux::is_launch_at_startup_registered()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(false)
    }
}

/// Returns the registered startup command line string, if present.
pub fn get_startup_command() -> Result<Option<String>, Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        windows::get_startup_command()
    }
    #[cfg(target_os = "linux")]
    {
        linux::get_startup_command()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(None)
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::error::Error;
    use std::path::PathBuf;

    const HKEY_CURRENT_USER: isize = 0x80000001u32 as i32 as isize;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const REG_SZ: u32 = 1;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const VALUE_NAME: &str = "NoteVault";

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            hKey: isize,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut isize,
        ) -> i32;

        fn RegSetValueExW(
            hKey: isize,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;

        fn RegDeleteValueW(hKey: isize, lpValueName: *const u16) -> i32;

        fn RegQueryValueExW(
            hKey: isize,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;

        fn RegCloseKey(hKey: isize) -> i32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn build_startup_cmd(exe_path: &PathBuf, minimized: bool) -> String {
        if minimized {
            format!("\"{}\" --minimized", exe_path.display())
        } else {
            format!("\"{}\"", exe_path.display())
        }
    }

    pub fn set_launch_at_startup(enabled: bool, minimized: bool) -> Result<(), Box<dyn Error>> {
        let subkey_w = to_wide(SUBKEY);
        let val_w = to_wide(VALUE_NAME);

        let mut hkey: isize = 0;
        let open_res = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
        };

        if open_res != 0 {
            return Err(format!("RegOpenKeyExW failed with code {}", open_res).into());
        }

        if enabled {
            let exe = std::env::current_exe()?;
            let cmd = build_startup_cmd(&exe, minimized);
            let cmd_w = to_wide(&cmd);
            let cb_data = (cmd_w.len() * std::mem::size_of::<u16>()) as u32;

            let set_res = unsafe {
                RegSetValueExW(
                    hkey,
                    val_w.as_ptr(),
                    0,
                    REG_SZ,
                    cmd_w.as_ptr() as *const u8,
                    cb_data,
                )
            };
            let _ = unsafe { RegCloseKey(hkey) };

            if set_res != 0 {
                return Err(format!("RegSetValueExW failed with code {}", set_res).into());
            }
        } else {
            let del_res = unsafe { RegDeleteValueW(hkey, val_w.as_ptr()) };
            let _ = unsafe { RegCloseKey(hkey) };

            if del_res != 0 && del_res != ERROR_FILE_NOT_FOUND {
                return Err(format!("RegDeleteValueW failed with code {}", del_res).into());
            }
        }

        Ok(())
    }

    pub fn is_launch_at_startup_registered() -> Result<bool, Box<dyn Error>> {
        let subkey_w = to_wide(SUBKEY);
        let val_w = to_wide(VALUE_NAME);

        let mut hkey: isize = 0;
        let open_res = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut hkey,
            )
        };

        if open_res != 0 {
            return Ok(false);
        }

        let mut data_type: u32 = 0;
        let mut cb_data: u32 = 0;
        let query_res = unsafe {
            RegQueryValueExW(
                hkey,
                val_w.as_ptr(),
                std::ptr::null_mut(),
                &mut data_type,
                std::ptr::null_mut(),
                &mut cb_data,
            )
        };
        let _ = unsafe { RegCloseKey(hkey) };

        Ok(query_res == 0)
    }

    pub fn get_startup_command() -> Result<Option<String>, Box<dyn Error>> {
        let subkey_w = to_wide(SUBKEY);
        let val_w = to_wide(VALUE_NAME);

        let mut hkey: isize = 0;
        let open_res = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut hkey,
            )
        };

        if open_res != 0 {
            return Ok(None);
        }

        let mut data_type: u32 = 0;
        let mut cb_data: u32 = 0;
        let query_res = unsafe {
            RegQueryValueExW(
                hkey,
                val_w.as_ptr(),
                std::ptr::null_mut(),
                &mut data_type,
                std::ptr::null_mut(),
                &mut cb_data,
            )
        };

        if query_res != 0 || cb_data == 0 {
            let _ = unsafe { RegCloseKey(hkey) };
            return Ok(None);
        }

        let mut buffer: Vec<u8> = vec![0u8; cb_data as usize];
        let fetch_res = unsafe {
            RegQueryValueExW(
                hkey,
                val_w.as_ptr(),
                std::ptr::null_mut(),
                &mut data_type,
                buffer.as_mut_ptr(),
                &mut cb_data,
            )
        };
        let _ = unsafe { RegCloseKey(hkey) };

        if fetch_res != 0 {
            return Ok(None);
        }

        let wide_chars: &[u16] = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr() as *const u16, (cb_data as usize) / 2)
        };
        let end = wide_chars
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(wide_chars.len());
        Ok(Some(String::from_utf16_lossy(&wide_chars[..end])))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;

    fn get_autostart_path() -> Option<PathBuf> {
        if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
            let p = PathBuf::from(config_home).join("autostart/note-vault.desktop");
            return Some(p);
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home).join(".config/autostart/note-vault.desktop");
            return Some(p);
        }
        None
    }

    pub fn set_launch_at_startup(enabled: bool, minimized: bool) -> Result<(), Box<dyn Error>> {
        let Some(path) = get_autostart_path() else {
            return Ok(());
        };

        if enabled {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let exe = std::env::current_exe()?;
            let exec_cmd = if minimized {
                format!("\"{}\" --minimized", exe.display())
            } else {
                format!("\"{}\"", exe.display())
            };
            let path_entry = if let Some(parent) = exe.parent() {
                format!("Path={}\n", parent.display())
            } else {
                String::new()
            };
            let content = format!(
                "[Desktop Entry]\n\
                 Type=Application\n\
                 Version=1.0\n\
                 Name=NoteVault\n\
                 Comment=Secure Encrypted Notes\n\
                 Exec={}\n\
                 {}Terminal=false\n\
                 StartupNotify=false\n",
                exec_cmd,
                path_entry
            );
            fs::write(&path, content)?;
        } else if path.exists() {
            let _ = fs::remove_file(&path);
        }

        Ok(())
    }

    pub fn is_launch_at_startup_registered() -> Result<bool, Box<dyn Error>> {
        let Some(path) = get_autostart_path() else {
            return Ok(false);
        };
        Ok(path.exists())
    }

    pub fn get_startup_command() -> Result<Option<String>, Box<dyn Error>> {
        let Some(path) = get_autostart_path() else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)?;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("Exec=") {
                return Ok(Some(rest.trim().to_string()));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_build_startup_cmd() {
        let path = PathBuf::from("C:\\Program Files\\NoteVault\\note_vault.exe");
        let non_minimized = windows::build_startup_cmd(&path, false);
        assert_eq!(non_minimized, "\"C:\\Program Files\\NoteVault\\note_vault.exe\"");

        let minimized = windows::build_startup_cmd(&path, true);
        assert_eq!(
            minimized,
            "\"C:\\Program Files\\NoteVault\\note_vault.exe\" --minimized"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_set_and_query_startup_lifecycle() {
        // Test registering with minimized=true
        let res = set_launch_at_startup(true, true);
        assert!(res.is_ok(), "Setting launch at startup should succeed: {:?}", res);

        let registered = is_launch_at_startup_registered().unwrap();
        assert!(registered, "Should be registered");

        let cmd = get_startup_command().unwrap();
        assert!(cmd.is_some(), "Command should be present");
        let cmd_str = cmd.unwrap();
        assert!(cmd_str.contains("--minimized"), "Should contain --minimized: {}", cmd_str);

        // Test updating to minimized=false
        let res2 = set_launch_at_startup(true, false);
        assert!(res2.is_ok());
        let cmd2 = get_startup_command().unwrap().unwrap();
        assert!(!cmd2.contains("--minimized"), "Should NOT contain --minimized: {}", cmd2);

        // Test unregistering
        let res3 = set_launch_at_startup(false, false);
        assert!(res3.is_ok());
        let registered_after = is_launch_at_startup_registered().unwrap();
        assert!(!registered_after, "Should be unregistered");
    }
}
