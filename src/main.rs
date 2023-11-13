macro_rules! error {
    () => {
        eprintln!()
    };
    ($($arg: tt)*) => {{
        eprint!("[31mError:[m ");
        eprintln!($($arg)*);
    }};
}

mod args;
mod crypt;

const BUF_LEN: usize = 8 * 1024;

fn main() -> std::process::ExitCode {
    if let Err(err) = fallible_main() {
        error!("{err:?}");
        return std::process::ExitCode::FAILURE;
    }

    std::process::ExitCode::SUCCESS
}

fn fallible_main() -> anyhow::Result<()> {
    let command = args::parse()?;

    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();

    match command {
        args::Command::Encrypt(key) => encrypt(key, stdin, stdout),
        args::Command::Decrypt(key) => decrypt(key, stdin, stdout),
    }
}

fn encrypt<Input, Output>(key: [u8; 32], input: Input, output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    let encryptor = crypt::Cryptor::new(key, output)?;
    stream(input, zstd::Encoder::new(encryptor, 9)?.auto_finish())
}

fn decrypt<Input, Output>(key: [u8; 32], input: Input, output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    let decryptor = crypt::Decryptor::new(key, input)?;
    stream(zstd::Decoder::new(decryptor)?, output)
}

fn stream<Input, Output>(mut input: Input, mut output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    use anyhow::Context;

    let mut buf = make_buffer::<BUF_LEN>();

    loop {
        let bytes = input.read(&mut buf).context("Error while reading")?;

        if bytes == 0 {
            return Ok(());
        }

        output.write_all(&buf[..bytes])?;
    }
}

#[allow(clippy::uninit_assumed_init)]
fn make_buffer<const L: usize>() -> [u8; L] {
    unsafe { std::mem::MaybeUninit::uninit().assume_init() }
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

        encrypt([0; 32], input.as_slice(), &mut transient).unwrap();
        assert_ne!(input, transient);
        decrypt([0; 32], transient.as_slice(), &mut output).unwrap();

        assert_eq!(input, output);
    }
}
