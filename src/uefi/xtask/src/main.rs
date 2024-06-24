//! A build and test assist program. To show the usage, run
//!
//! ```shell
//! cargo xtask
//! ```

use cargo::{cargo_run, Action, Package, Profile};
use clap::{Parser, Subcommand};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use vmtest::{
    bochs::{Bochs, Cpu},
    vmware::Vmware,
};

mod cargo;
mod vmtest;

pub(crate) type DynError = Box<dyn std::error::Error>;

#[derive(Parser)]
#[command(author, about, long_about = None)]
struct Cli {
    /// Build the hypervisor with the release profile
    #[arg(short, long)]
    release: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the entire workspace
    Build,
    /// Run clippy for the entire workspace
    Clippy,
    /// Start a Bochs VM with an Intel processor
    BochsIntel,
    /// Start a Bochs VM with an AMD processor
    BochsAmd,
    /// Start a VMware VM
    Vmware,
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Commands::Build => build(cli.release),
        Commands::Clippy => clippy(),
        Commands::BochsIntel => vmtest::run(&Bochs { cpu: Cpu::Intel }, cli.release),
        Commands::BochsAmd => vmtest::run(&Bochs { cpu: Cpu::Amd }, cli.release),
        Commands::Vmware => vmtest::run(&Vmware {}, cli.release),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(-1);
    }
}

fn build(release: bool) -> Result<(), DynError> {
    let profile = if release {
        Profile::Release
    } else {
        Profile::Debug
    };
    cargo_run(Action::Build, Package::Hypervisor, profile)?;
    cargo_run(Action::Build, Package::CheckHvVendor, profile)
}

fn clippy() -> Result<(), DynError> {
    cargo_run(Action::Clippy, Package::Hypervisor, Profile::Debug)?;
    cargo_run(Action::Clippy, Package::CheckHvVendor, Profile::Debug)?;
    cargo_run(Action::Clippy, Package::Xtask, Profile::Debug)
}

fn output_dir(release: bool) -> PathBuf {
    let mut out_dir = project_root_dir();
    out_dir.extend(&["target", "x86_64-unknown-uefi"]);
    out_dir.extend(if release { &["release"] } else { &["debug"] });
    fs::canonicalize(&out_dir).unwrap()
}

fn project_root_dir() -> PathBuf {
    // Get the path to the xtask directory and resolve its parent directory.
    let root_dir = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf();
    fs::canonicalize(root_dir).unwrap()
}
