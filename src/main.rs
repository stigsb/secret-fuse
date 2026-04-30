use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod config;
mod fs;
mod resolver;
mod service;
mod template;

#[derive(Parser)]
#[command(name = "secret-fuse", about = "FUSE filesystem for 1Password secrets")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "~/.config/secretfuse/config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount the secret filesystem (foreground)
    Mount {
        /// Run as background daemon
        #[arg(long)]
        daemon: bool,
    },
    /// Unmount the secret filesystem
    Unmount,
    /// Validate config and templates without fetching secrets
    Check,
    /// Install as system service (launchd/systemd)
    Install,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Mount { daemon } => {
            eprintln!("mount (daemon={daemon}) not yet implemented");
        }
        Commands::Unmount => {
            eprintln!("unmount not yet implemented");
        }
        Commands::Check => {
            eprintln!("check not yet implemented");
        }
        Commands::Install => {
            eprintln!("install not yet implemented");
        }
    }
}
