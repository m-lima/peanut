pub fn btrfs(use_sudo: bool) -> anyhow::Result<(Option<String>, String)> {
    let btrfs = find("btrfs")?;

    let sudo = if use_sudo { Some(find("sudo")?) } else { None };

    if let Some(ref sudo) = sudo {
        log::info!("Using `{sudo} {btrfs}` as the binary");
    } else {
        log::info!("Using `{btrfs}` as the binary");
    };

    Ok((sudo, btrfs))
}

fn find(command: &str) -> anyhow::Result<String> {
    let stdout = std::process::Command::new("/usr/bin/env")
        .arg("which")
        .arg(command)
        .tee()?;

    if stdout.is_empty() {
        Err(anyhow::anyhow!("Could not find executable for {command}"))
    } else {
        Ok(String::from(stdout.trim()))
    }
}

pub fn prepare(sudo: &Option<String>, command: &str) -> std::process::Command {
    if let Some(sudo) = sudo {
        let mut cmd = std::process::Command::new(sudo);
        cmd.arg(command);
        cmd
    } else {
        std::process::Command::new(command)
    }
}

pub trait Tee {
    fn tee(&mut self) -> anyhow::Result<String>;
}

impl Tee for std::process::Command {
    fn tee(&mut self) -> anyhow::Result<String> {
        let output = self.output()?;

        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            log::warn!("{stderr}");
        }

        String::from_utf8(output.stdout).map_err(Into::into)
    }
}
