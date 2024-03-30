use std::{path::Path, process::Command};

use crate::{build, cargo::Package, output_dir, project_root_dir, DynError};

pub(crate) mod bochs;
pub(crate) mod vmware;

pub(crate) trait TestVm {
    fn deploy(&self, release: bool) -> Result<(), DynError>;
    fn run(&self) -> Result<(), DynError>;
}

pub(crate) fn run<T: TestVm>(vm: &T, release: bool) -> Result<(), DynError> {
    build(release)?;
    extract_samples()?;
    vm.deploy(release)?;
    vm.run()
}

fn copy_artifacts_to(image: &str, release: bool) -> Result<(), DynError> {
    let files = [
        unix_path(&output_dir(release)) + "/" + Package::Hypervisor.name() + ".efi",
        unix_path(&output_dir(release)) + "/" + Package::CheckHvVendor.name() + ".efi",
        unix_path(&project_root_dir()) + "/tests/startup.nsh",
    ];
    for file in &files {
        let output = UnixCommand::new("mcopy")
            .args(["-o", "-i", image, file, "::/"])
            .output()?;
        if !output.status.success() {
            Err(format!("mcopy failed: {output:#?}"))?;
        }
    }
    Ok(())
}

fn extract_samples() -> Result<(), DynError> {
    if !Path::new("./tests/samples/").exists() {
        println!("Extracting sample files...");
        let output = UnixCommand::new("7z")
            .args(["x", "-o./tests/", "./tests/samples.7z"])
            .output()?;
        if !output.status.success() {
            Err(format!("7z failed: {output:#?}"))?;
        }
    }
    Ok(())
}

fn unix_path(path: &Path) -> String {
    if cfg!(target_os = "windows") {
        let path_str = path.to_str().unwrap().replace('\\', "\\\\");
        let output = UnixCommand::new("wslpath")
            .args(["-a", &path_str])
            .output()
            .unwrap();
        std::str::from_utf8(&output.stdout)
            .unwrap()
            .trim()
            .to_string()
    } else {
        path.to_str().unwrap().to_string()
    }
}

// Defines [`UnixCommand`] that wraps [`Command`] with `wsl` command on Windows.
// On non-Windows platforms, it is an alias of [`Command`].
cfg_if::cfg_if! {
    if #[cfg(windows)] {
        struct UnixCommand {
            wsl: Command,
            program: String,
        }

        impl UnixCommand {
            fn new(program: &str) -> Self {
                Self {
                    wsl: Command::new("wsl"),
                    program: program.to_string(),
                }
            }

            pub(crate) fn args<I, S>(&mut self, args: I) -> &mut Command
            where
                I: IntoIterator<Item = S>,
                S: AsRef<std::ffi::OsStr>,
            {
                self.wsl.arg(self.program.clone()).args(args)
            }
        }
    } else {
        type UnixCommand = Command;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_unix_path() {
        if cfg!(target_os = "windows") {
            assert_eq!(unix_path(Path::new(r"C:\")), "/mnt/c/");
            assert_eq!(unix_path(Path::new("/tmp")), "/mnt/c/tmp");
        } else {
            assert_eq!(unix_path(Path::new(r"C:\")), r"C:\");
            assert_eq!(unix_path(Path::new("/tmp")), "/tmp");
        }
    }
}
