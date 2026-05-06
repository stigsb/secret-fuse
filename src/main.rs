use clap::{Parser, Subcommand};
use log::info;
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

mod cache_crypto;
mod config;
mod fs;
mod harden;
mod resolver;
mod service;
mod template;

use cache_crypto::CacheKey;
use config::Config;
use resolver::SecretResolver;
use template::TemplateEngine;

#[derive(Parser)]
#[command(name = "secret-fuse", about = "FUSE filesystem for 1Password secrets")]
struct Cli {
    #[arg(short, long, default_value = "~/.config/secretfuse/config.yaml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Mount {
        #[arg(long)]
        daemon: bool,
    },
    Unmount,
    Check,
    Install,
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

fn init_logging() {
    #[cfg(target_os = "macos")]
    {
        let stderr_is_tty = unsafe { libc::isatty(libc::STDERR_FILENO) } != 0;
        if !stderr_is_tty
            && oslog::OsLogger::new("com.stigbakken.secret-fuse")
                .level_filter(log::LevelFilter::Info)
                .init()
                .is_ok()
        {
            return;
        }
    }
    env_logger::init();
}

fn main() {
    init_logging();
    let cli = Cli::parse();
    let config_path = expand_tilde(&cli.config);

    match cli.command {
        Commands::Mount { daemon } => {
            if daemon {
                eprintln!("Daemon mode not yet implemented. Running in foreground.");
            }
            cmd_mount(config_path);
        }
        Commands::Unmount => cmd_unmount(config_path),
        Commands::Check => cmd_check(config_path),
        Commands::Install => cmd_install(config_path),
    }
}

fn cmd_mount(config_path: PathBuf) {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = config.validate() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    // Check that `op` is available
    match std::process::Command::new("op").arg("--version").output() {
        Ok(output) if output.status.success() => {
            info!(
                "1Password CLI: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        _ => {
            eprintln!(
                "Error: 1Password CLI (op) not found. Install it: https://developer.1password.com/docs/cli/"
            );
            std::process::exit(1);
        }
    }

    // Harden process before loading any secrets
    harden::harden_process();

    let resolver = Arc::new(SecretResolver::new(
        Duration::from_secs(config.cache_ttl),
        Duration::from_secs(config.op_timeout),
        Arc::new(CacheKey::new()),
    ));
    let engine = Arc::new(TemplateEngine::new(Arc::clone(&resolver)));
    let mountpoint = config.mountpoint.clone();
    let filesystem = fs::SecretFs::new(config.files, engine);

    // Clear secret caches on SIGHUP
    let sighup_resolver = Arc::clone(&resolver);
    let mut signals = Signals::new([SIGHUP]).expect("failed to register SIGHUP handler");
    std::thread::spawn(move || {
        for _ in signals.forever() {
            info!("SIGHUP received, clearing secret cache");
            sighup_resolver.clear_cache();
        }
    });

    eprintln!("Mounting secret-fuse at {}", mountpoint.display());
    eprintln!("Press Ctrl-C to unmount and exit. Send SIGHUP to clear caches.");

    if let Err(e) = fs::mount(filesystem, &mountpoint) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_unmount(config_path: PathBuf) {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let mountpoint = config.mountpoint.to_string_lossy().to_string();

    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("umount")
        .arg(&mountpoint)
        .status();
    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("fusermount")
        .args(["-u", &mountpoint])
        .status();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: Result<std::process::ExitStatus, std::io::Error> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported platform",
    ));

    match result {
        Ok(status) if status.success() => eprintln!("Unmounted {mountpoint}"),
        Ok(status) => {
            eprintln!(
                "Unmount failed (exit code: {})",
                status.code().unwrap_or(-1)
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Unmount failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_check(config_path: PathBuf) {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = config.validate() {
        eprintln!("Validation error: {e}");
        std::process::exit(1);
    }

    let resolver = Arc::new(SecretResolver::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Arc::new(CacheKey::new()),
    ));
    let engine = TemplateEngine::new(resolver);

    let mut errors = 0;
    for (path, entry) in &config.files {
        let result = match &entry.source {
            config::FileSource::Content(_) => Ok(()),
            config::FileSource::Template(t) => engine.validate_syntax(t),
            config::FileSource::TemplateFile(p) => match std::fs::read_to_string(p) {
                Ok(contents) => engine.validate_syntax(&contents),
                Err(e) => {
                    eprintln!("  FAIL {path}: {e}");
                    errors += 1;
                    continue;
                }
            },
            config::FileSource::Secret(_) => Ok(()),
        };

        match result {
            Ok(()) => eprintln!("  OK   {path}"),
            Err(e) => {
                eprintln!("  FAIL {path}: {e}");
                errors += 1;
            }
        }
    }

    if errors > 0 {
        eprintln!("\n{errors} error(s) found.");
        std::process::exit(1);
    } else {
        eprintln!("\nAll templates valid.");
    }
}

fn cmd_install(config_path: PathBuf) {
    let config = match Config::load(config_path.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    match service::install(&config_path, &config.mountpoint) {
        Ok(path) => {
            eprintln!("Service file written to: {}", path.display());
            #[cfg(target_os = "macos")]
            eprintln!("To load: launchctl load {}", path.display());
            #[cfg(target_os = "linux")]
            eprintln!("To enable: systemctl --user enable --now secret-fuse");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}
