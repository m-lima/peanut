use crate::{
    args::List,
    command::{self, Tee},
};

pub fn run(list: List) -> anyhow::Result<()> {
    let (sudo, btrfs) = command::btrfs(list.use_sudo)?;

    let stdout = command::prepare(&sudo, &btrfs)
        .arg("subvolume")
        .arg("list")
        .arg("/")
        .tee()?;

    let subvolumes = stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();

            let Some(level) = parts.nth(6) else {
                log::info!("Malformed line found: {line}");
                return None;
            };

            let Ok(level) = level.parse::<i64>() else {
                log::info!("Malformed line found: {line}");
                return None;
            };

            if level >= 256 {
                return None;
            }

            let Some(name) = parts.nth(1) else {
                log::info!("Malformed line found: {line}");
                return None;
            };

            Some(String::from(name))
        })
        .collect::<Vec<_>>();

    Ok(())
}
