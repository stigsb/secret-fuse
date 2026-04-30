use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("failed to write service file: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not determine current executable path")]
    NoExePath,
    #[error("unsupported platform for service installation")]
    #[allow(dead_code)]
    UnsupportedPlatform,
}

pub fn install(config_path: &Path, _mountpoint: &Path) -> Result<PathBuf, ServiceError> {
    let exe = std::env::current_exe().map_err(|_| ServiceError::NoExePath)?;

    #[cfg(target_os = "macos")]
    return install_launchd(&exe, config_path);
    #[cfg(target_os = "linux")]
    return install_systemd(&exe, config_path);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    Err(ServiceError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
fn install_launchd(exe: &Path, config_path: &Path) -> Result<PathBuf, ServiceError> {
    let plist_dir = dirs::home_dir().unwrap_or_default().join("Library/LaunchAgents");
    std::fs::create_dir_all(&plist_dir)?;
    let plist_path = plist_dir.join("ai.sunstoneinstitute.secret-fuse.plist");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.sunstoneinstitute.secret-fuse</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--config</string>
        <string>{config}</string>
        <string>mount</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/secret-fuse.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/secret-fuse.stderr.log</string>
</dict>
</plist>
"#,
        exe = exe.display(),
        config = config_path.display(),
    );
    std::fs::write(&plist_path, plist)?;
    Ok(plist_path)
}

#[cfg(target_os = "linux")]
fn install_systemd(exe: &Path, config_path: &Path) -> Result<PathBuf, ServiceError> {
    let unit_dir = dirs::home_dir().unwrap_or_default().join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let unit_path = unit_dir.join("secret-fuse.service");
    let unit = format!(
        r#"[Unit]
Description=secret-fuse - FUSE filesystem for 1Password secrets
After=network.target

[Service]
Type=simple
ExecStart={exe} --config {config} mount
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#,
        exe = exe.display(),
        config = config_path.display(),
    );
    std::fs::write(&unit_path, unit)?;
    Ok(unit_path)
}
