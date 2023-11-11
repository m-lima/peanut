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
    use anyhow::Context;

    let mut command = std::process::Command::new(args.command);
    command.args(args.args);
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .context("Failed to spawn the child process")?;

    let Some(stdout) = child.stdout.take() else {
        anyhow::bail!("Failed to attach to the child process's stdout");
    };

    let Some(stderr) = child.stderr.take() else {
        anyhow::bail!("Failed to attach to the child process's stderr");
    };

    let (stdout, stderr) = match args.mode {
        args::Mode::Stdout => (
            std::thread::spawn(compress(stdout, "stdout")),
            std::thread::spawn(echo(stderr, "stderr")),
        ),
        args::Mode::Stderr => (
            std::thread::spawn(echo(stdout, "stdout")),
            std::thread::spawn(compress(stderr, "stderr")),
        ),
        args::Mode::Both => (
            std::thread::spawn(compress(stdout, "stdout")),
            std::thread::spawn(compress(stderr, "stderr")),
        ),
    };

    if stdout.join().is_err() {
        anyhow::bail!("The listener for the child process's stdout panicked");
    }
    if stderr.join().is_err() {
        anyhow::bail!("The listener for the child process's stderr panicked");
    }
    child.wait().map_err(Into::into)
}

fn compress<Src>(src: Src, name: &'static str) -> impl FnOnce()
where
    Src: std::io::Read,
{
    // TODO: just bypassing for now
    echo(src, name)
}

fn echo<Src>(src: Src, name: &'static str) -> impl FnOnce()
where
    Src: std::io::Read,
{
    use std::io::Write;

    move || {
        let mut buf = [0; 8 * 1024];
        let mut src = src;
        let mut dst = std::io::stderr();

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
