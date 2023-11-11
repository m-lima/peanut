macro_rules! error {
    () => {
        eprintln!()
    };
    ($($arg:tt)*) => {{
        eprint!("[31mError:[m ");
        eprintln!($($arg)*);
    }};
}

mod args;

fn main() -> std::process::ExitCode {
    let args = args::parse();

    let status = match fallible_main(args) {
        Ok(status) => status,
        Err(err) => {
            error!("{err:?}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if status.success() {
        std::process::ExitCode::SUCCESS
    } else {
        let Some(status) = status.code() else {
            error!("The child process was terminated by a signal");
            return std::process::ExitCode::FAILURE;
        };

        let Ok(status) = u8::try_from(status) else {
            error!("Could not convert the child process's exit code");
            std::process::exit(status);
        };

        status.into()
    }
}

fn fallible_main(args: args::Args) -> anyhow::Result<std::process::ExitStatus> {
    let mut command = std::process::Command::new(args.command);
    command.args(args.args);
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
                    error!("Error while reading {name}: {err}");
                    return;
                }
            };

            if bytes == 0 {
                return;
            }

            if let Err(err) = dst.write_all(&buf[..bytes]) {
                error!("Error while writing {name}: {err}");
                continue;
            }
        }
    }
}
