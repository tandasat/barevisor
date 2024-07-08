use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Command, Stdio},
    sync::mpsc::channel,
    thread,
    time::{Duration, SystemTime},
};

use anyhow::{ensure, Result};

use super::{copy_artifacts_to, TestVm, UnixCommand};

pub(crate) struct Vmware;

impl TestVm for Vmware {
    fn deploy(&self, release: bool) -> Result<()> {
        let output = UnixCommand::new("dd")
            .args([
                "if=/dev/zero",
                "of=/tmp/vmware_cd.img",
                "bs=1k",
                "count=2880",
            ])
            .output()?;
        ensure!(output.status.success(), format!("dd failed: {output:#?}"));

        let output = UnixCommand::new("mformat")
            .args(["-i", "/tmp/vmware_cd.img", "-f", "2880", "::"])
            .output()?;
        ensure!(
            output.status.success(),
            format!("mformat failed: {output:#?}")
        );

        copy_artifacts_to("/tmp/vmware_cd.img", release)?;

        let output = UnixCommand::new("mkisofs")
            .args([
                "-eltorito-boot",
                "vmware_cd.img",
                "-no-emul-boot",
                "-o",
                "/tmp/vmware_cd.iso",
                "/tmp/vmware_cd.img",
            ])
            .output()?;
        ensure!(
            output.status.success(),
            format!("mkisofs failed: {output:#?}")
        );

        Ok(())
    }

    fn run(&self) -> Result<()> {
        let vmrun = if cfg!(target_os = "windows") {
            r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
        } else if wsl::is_wsl() {
            "/mnt/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe"
        } else {
            "vmrun"
        };

        let vmx_path = if wsl::is_wsl() {
            windows_path("./tests/samples/vmware/NoOS_windows.vmx")
        } else {
            format!("./tests/samples/vmware/NoOS_{}.vmx", env::consts::OS)
        };

        // Stop the VM if requested. This is best effort and failures are ignored.
        let _unused = Command::new(vmrun)
            .args(["stop", vmx_path.as_str(), "nogui"])
            .output()?;

        // If the serial output file exists, delete it to avoid a prompt.
        let log_file = if cfg!(target_os = "windows") {
            r"\\wsl$\Ubuntu\tmp\serial.log"
        } else {
            "/tmp/serial.log"
        };
        if Path::new(log_file).exists() {
            fs::remove_file(log_file)?;
        }

        // If the "forceSetupOnce" entry is not in the .vmx file already, append
        // it to boot into the BIOS menu automatically. This entry is automatically
        // deleted by VMWare after each boot, so we need to add it every time.
        let entry_name = "bios.forceSetupOnce";
        let entry_exists = BufReader::new(fs::File::open(&vmx_path)?)
            .lines()
            .any(|line| line.unwrap().starts_with(entry_name));
        if !entry_exists {
            let mut file = fs::OpenOptions::new().append(true).open(&vmx_path)?;
            writeln!(file, "{entry_name} = \"TRUE\"")?;
        }

        // Start the VM.
        println!("🕒 Starting the VMware VM");
        let product_type = if cfg!(target_os = "macos") {
            "fusion"
        } else {
            "ws"
        };
        let output = Command::new(vmrun)
            .args(["-T", product_type, "start", vmx_path.as_str()])
            .spawn()?
            .wait()?;
        ensure!(output.success(), format!("vmrun failed: {output:#?}"));

        // Wait until the serial output file is created. Then, enter loop to read it.
        while !Path::new(log_file).exists() {
            thread::sleep(Duration::from_secs(1));
        }

        let _unused = thread::spawn(|| {
            let output = UnixCommand::new("tail")
                .args(["-f", "/tmp/serial.log"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            let now = SystemTime::now();

            // Read and print stdout as they come in. This does not return.
            let reader = BufReader::new(output.stdout.unwrap());
            reader.lines().map_while(Result::ok).for_each(|line| {
                println!(
                    "{:>4}: {line}\r",
                    now.elapsed().unwrap_or_default().as_secs()
                );
            });
        });

        println!("🕒 Please select 'EFI Internal Shell (Unsupported option)' on VMware...");
        let (tx, rx) = channel();
        ctrlc::set_handler(move || tx.send(()).unwrap())?;
        rx.recv()?;

        // Stop the VM if requested. This is best effort and failures are ignored.
        println!("🕒 Shutting down the VM\r");
        let _unused = Command::new(vmrun)
            .args(["stop", vmx_path.as_str(), "nogui"])
            .output()?;

        Ok(())
    }
}

fn windows_path(path: &str) -> String {
    if wsl::is_wsl() {
        let output = UnixCommand::new("wslpath")
            .args(["-a", "-w", path])
            .output()
            .unwrap();
        assert!(output.status.success());
        std::str::from_utf8(&output.stdout)
            .unwrap()
            .trim()
            .to_string()
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::vmtest::vmware::windows_path;

    #[test]
    fn test_windows_path() {
        if cfg!(target_os = "windows") {
            assert_eq!(windows_path(r"C:\"), r"C:\");
            assert_eq!(windows_path("/mnt/c/tmp"), "/mnt/c/tmp");
        } else {
            assert_eq!(windows_path("/tmp"), r"\\wsl.localhost\Ubuntu\tmp");
        }
    }
}
