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
    let command = args::parse();

    if let Err(err) = fallible_main(command) {
        error!("{err:?}");
        return std::process::ExitCode::FAILURE;
    }

    std::process::ExitCode::SUCCESS
}

fn fallible_main(command: args::Command) -> anyhow::Result<()> {
    match command {
        args::Command::Encrypt(_) => stream(
            std::io::stdin().lock(),
            zstd::Encoder::new(std::io::stdout().lock(), 9)?.auto_finish(),
        ),
        args::Command::Decrypt(_) => stream(
            zstd::Decoder::new(std::io::stdin().lock())?,
            std::io::stdout().lock(),
        ),
    }
}

fn stream<Input, Output>(mut input: Input, mut output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    use anyhow::Context;

    const BUF_LEN: usize = 8 * 1024;

    let mut buf = unsafe {
        std::mem::transmute::<_, [u8; BUF_LEN]>([std::mem::MaybeUninit::<u8>::uninit(); BUF_LEN])
    };

    loop {
        let bytes = input
            .read(&mut buf)
            .context("Error while reading from stdin")?;

        if bytes == 0 {
            return Ok(());
        }

        if let Err(err) = output.write_all(&buf[..bytes]) {
            error!("Error while writing to stdout: {err}");
        }
    }
}
