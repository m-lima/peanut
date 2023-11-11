mod args;

fn init_logger(level: log::LevelFilter) -> Result<(), log::SetLoggerError> {
    simplelog::TermLogger::init(
        level,
        match simplelog::ConfigBuilder::default()
            .set_thread_level(log::LevelFilter::Trace)
            .set_time_offset_to_local()
        {
            Ok(b) => b.set_time_format_custom(simplelog::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second]"
            )),
            Err(b) => b.set_time_format_custom(simplelog::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
            )),
        }
        .build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    log::info!("Log level set to {level}");
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args = args::parse();

    if let Err(err) = init_logger(args.verbosity) {
        eprintln!("[31mError:[m {err}");
        return std::process::ExitCode::FAILURE;
    }

    let status = match fallible_main(args) {
        Ok(status) => status,
        Err(err) => {
            log::error!("{err}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if status.success() {
        std::process::ExitCode::SUCCESS
    } else {
        let Some(status) = status.code() else {
            log::error!("The child process was terminated by a signal");
            return std::process::ExitCode::FAILURE;
        };

        let Ok(status) = u8::try_from(status) else {
            log::error!("Could not convert the child process's exit code");
            std::process::exit(status);
        };

        status.into()
    }
}

fn fallible_main(args: args::Args) -> anyhow::Result<std::process::ExitStatus> {
    let mut command_parts = args.command.into_iter();

    let Some(command) = command_parts.next() else {
        anyhow::bail!("Nothing to execute");
    };

    let mut command = std::process::Command::new(command);
    command.args(command_parts);
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = anyhow::Context::context(command.spawn(), "Failed to spawn the child process")?;

    let Some(stdout) = child.stdout.take() else {
        anyhow::bail!("Failed to attach to the child process's stdout");
    };

    let Some(stderr) = child.stderr.take() else {
        anyhow::bail!("Failed to attach to the child process's stderr");
    };

    std::thread::spawn(make_listener(stdout, std::io::stdout(), "stdout"));
    std::thread::spawn(make_listener(stderr, std::io::stdout(), "stderr"));

    child.wait().map_err(Into::into)
}

fn make_listener<Src, Dst>(src: Src, dst: Dst, name: &'static str) -> impl FnOnce()
where
    Src: std::io::Read,
    Dst: std::io::Write,
{
    move || {
        let mut buf = [0; 4 * 1024];
        let mut src = src;
        let mut dst = dst;

        loop {
            let bytes = match src.read(&mut buf) {
                Ok(bytes) => bytes,
                Err(err) => {
                    log::error!("Error while reading {name}: {err}");
                    return;
                }
            };

            if bytes == 0 {
                log::debug!("Stopping stderr reader");
                return;
            }

            if let Err(err) = dst.write_all(&buf[..bytes]) {
                log::warn!("Error while writing stderr: {err}");
                continue;
            }
        }
    }
}
