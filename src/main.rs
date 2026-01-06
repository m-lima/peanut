#![deny(warnings, clippy::pedantic, clippy::all, rust_2018_idioms)]

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
        args::Command::Encrypt(mode) => encrypt(mode, stdin, stdout),
        args::Command::Decrypt(mode) => decrypt(mode, stdin, stdout),
    }
}

fn encrypt<Input, Output>(mode: args::Mode, input: Input, mut output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    match mode {
        args::Mode::Stream(key) => {
            let encrypter = match key {
                args::Key::Raw(key) => crypter::stream::Encrypter::new(&key, output)?,
                args::Key::Pwd(pwd) => crypter::stream::Encrypter::new_with_password(pwd, output)?,
            };
            stream(input, zstd::Encoder::new(encrypter, 9)?.auto_finish())
        }
        args::Mode::Full(key) => {
            let mut buffer = Vec::new();
            stream(input, zstd::Encoder::new(&mut buffer, 9)?.auto_finish())?;
            let encrypted = match key {
                args::Key::Raw(key) => crypter::encrypt(&key, buffer),
                args::Key::Pwd(pwd) => crypter::encrypt_with_password(&pwd, buffer),
            }
            .ok_or_else(|| anyhow::anyhow!("Failed to encrypt"))?;
            output.write_all(&encrypted).map_err(Into::into)
        }
    }
}

fn decrypt<Input, Output>(mode: args::Mode, mut input: Input, output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    match mode {
        args::Mode::Stream(key) => {
            let decrypter = match key {
                args::Key::Raw(key) => crypter::stream::Decrypter::new(&key, input)?,
                args::Key::Pwd(pwd) => crypter::stream::Decrypter::new_with_password(pwd, input)?,
            };
            stream(zstd::Decoder::new(decrypter)?, output)
        }
        args::Mode::Full(key) => {
            let mut buffer = Vec::new();
            input.read_to_end(&mut buffer)?;
            let decrypted = match key {
                args::Key::Raw(key) => crypter::decrypt(&key, buffer),
                args::Key::Pwd(pwd) => crypter::decrypt_with_password(pwd, buffer),
            }
            .map(std::io::Cursor::new)
            .ok_or_else(|| anyhow::anyhow!("Failed to decrypt"))?;
            stream(zstd::Decoder::new(decrypted)?, output)
        }
    }
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

// ALLOW(clippy::uninit_assumed_init): I understand the UB, and this is to be used as a buffer
#[allow(clippy::uninit_assumed_init)]
fn make_buffer<const L: usize>() -> [u8; L] {
    // SAFETY: I understand the UB, and this is to be used as a buffer
    unsafe { std::mem::MaybeUninit::uninit().assume_init() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| u8::MIN..u8::MAX)
            .collect::<Vec<_>>();

        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        stream(input.as_slice(), &mut output).unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn stream_round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| u8::MIN..u8::MAX)
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        encrypt(
            args::Mode::Stream(args::Key::Raw([0; 32])),
            input.as_slice(),
            &mut transient,
        )
        .unwrap();
        assert_ne!(input, transient);
        decrypt(
            args::Mode::Stream(args::Key::Raw([0; 32])),
            transient.as_slice(),
            &mut output,
        )
        .unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn stream_round_trip_with_password() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| u8::MIN..u8::MAX)
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        encrypt(
            args::Mode::Stream(args::Key::Pwd(String::from("yo"))),
            input.as_slice(),
            &mut transient,
        )
        .unwrap();
        assert_ne!(input, transient);
        decrypt(
            args::Mode::Stream(args::Key::Pwd(String::from("yo"))),
            transient.as_slice(),
            &mut output,
        )
        .unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn full_round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| u8::MIN..u8::MAX)
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        encrypt(
            args::Mode::Full(args::Key::Raw([0; 32])),
            input.as_slice(),
            &mut transient,
        )
        .unwrap();
        assert_ne!(input, transient);
        decrypt(
            args::Mode::Full(args::Key::Raw([0; 32])),
            transient.as_slice(),
            &mut output,
        )
        .unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn full_round_trip_with_password() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| u8::MIN..u8::MAX)
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        encrypt(
            args::Mode::Full(args::Key::Pwd(String::from("yo"))),
            input.as_slice(),
            &mut transient,
        )
        .unwrap();
        assert_ne!(input, transient);
        decrypt(
            args::Mode::Full(args::Key::Pwd(String::from("yo"))),
            transient.as_slice(),
            &mut output,
        )
        .unwrap();

        assert_eq!(input, output);
    }
}
