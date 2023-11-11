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
        args::Command::Encrypt(_) => encrypt(std::io::stdin().lock(), std::io::stdout().lock()),
        args::Command::Decrypt(_) => decrypt(std::io::stdin().lock(), std::io::stdout().lock()),
    }
}

fn encrypt<Input, Output>(input: Input, output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    stream(input, zstd::Encoder::new(output, 9)?.auto_finish())
}

fn decrypt<Input, Output>(input: Input, output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    stream(zstd::Decoder::new(input)?, output)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        stream(input.as_slice(), &mut output).unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        encrypt(input.as_slice(), &mut transient).unwrap();
        decrypt(transient.as_slice(), &mut output).unwrap();

        assert_eq!(input, output);
    }
}
