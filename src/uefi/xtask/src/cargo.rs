use std::{env, fs, path::PathBuf, process::Command};

use anyhow::{ensure, Result};

use crate::{output_dir, project_root_dir};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Action {
    Build,
    Clippy,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Package {
    Hypervisor,
    CheckHvVendor,
    Xtask,
}

impl Package {
    pub(crate) fn name(&self) -> &str {
        match *self {
            Package::Hypervisor => "uefi_hv",
            Package::CheckHvVendor => "check_hv_vendor",
            Package::Xtask => "xtask",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Profile {
    Debug,
    Release,
}

pub(crate) fn cargo_run(action: Action, package: Package, profile: Profile) -> Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(cargo);
    let _ = command.arg(match action {
        Action::Build => "build",
        Action::Clippy => "clippy",
    });
    if uefi_target(package) {
        let _ = command.args(["--target", "x86_64-unknown-uefi"]);
    }
    let _ = command.args(["--package", package.name()]);
    let release = profile == Profile::Release;
    if release {
        let _ = command.arg("--release");
    }
    let ok = command.current_dir(project_root_dir()).status()?.success();
    ensure!(ok, "cargo build failed");

    if action == Action::Build && package == Package::Hypervisor {
        let hv_efi = output_dir(release).join(package.name().to_owned() + ".efi");
        transmute_to_runtime_driver(hv_efi)?;
    }

    Ok(())
}

fn uefi_target(package: Package) -> bool {
    package == Package::Hypervisor || package == Package::CheckHvVendor
}

fn transmute_to_runtime_driver(path: PathBuf) -> Result<()> {
    let mut data = fs::read(path.clone())?;
    data[0xd4] = 0xc; // IMAGE_OPTIONAL_HEADER.Subsystem = IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
    fs::write(path, data)?;
    Ok(())
}
