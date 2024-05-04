use crate::DynError;
use std::{
    env, fmt,
    io::{BufRead, BufReader},
    path::Path,
    process::Stdio,
    sync::mpsc::channel,
    thread,
    time::{Duration, SystemTime},
};

use super::{copy_artifacts_to, TestVm, UnixCommand};

pub(crate) struct Bochs {
    pub(crate) cpu: Cpu,
}

impl TestVm for Bochs {
    fn deploy(&self, release: bool) -> Result<(), DynError> {
        copy_artifacts_to("./tests/samples/bochs_disk.img", release)
    }

    fn run(&self) -> Result<(), DynError> {
        // Start a threads that tries to connect to Bochs in an infinite loop.
        let _unused = thread::spawn(|| loop {
            thread::sleep(Duration::from_secs(1));
            let output = UnixCommand::new("nc")
                .args(["localhost", "14449"])
                .stdout(Stdio::piped())
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();

            let now = SystemTime::now();
            let reader = BufReader::new(output.stdout.unwrap());
            reader.lines().map_while(Result::ok).for_each(|line| {
                println!(
                    "{:>4}: {line}\r",
                    now.elapsed().unwrap_or_default().as_secs()
                );
            });
        });

        let cpu_type = self.cpu.to_string().to_lowercase();
        let _unused = thread::spawn(move || {
            // Use WSL to launch Bochs on Windows as we anyway depends on telnet
            // on WSL. Not worth time to try to make Windows telnet work.
            let os_type = if cfg!(target_os = "windows") {
                "linux"
            } else {
                env::consts::OS
            };
            let bxrc = format!("./bochs/{os_type}_{cpu_type}.bxrc");

            // Start Bochs from the "tests" directory in background.
            let output = UnixCommand::new("bochs")
                .args(["-q", "-unlock", "-f", &bxrc])
                .current_dir(Path::new("./tests"))
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            // Read and print stdout as they come in. This does not return.
            let reader = BufReader::new(output.stdout.unwrap());
            reader
                .lines()
                .map_while(Result::ok)
                .for_each(|line| println!("{line}\r"));
        });

        let (tx, rx) = channel();
        ctrlc::set_handler(move || tx.send(()).unwrap())?;
        rx.recv()?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum Cpu {
    Intel,
    Amd,
}
impl fmt::Display for Cpu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
