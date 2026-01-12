macro_rules! arg_error {
    ($help: ident, $($arg:tt)*) => {{
        error!($($arg)*);
        error!();
        $help(&mut std::io::stderr());
        std::process::exit(1);
    }};
    ($($arg:tt)*) => {{
        error!($($arg)*);
        std::process::exit(1);
    }};
}

fn usage<Out>(mut out: Out)
where
    Out: std::io::Write,
{
    drop(writeln!(
        out,
        r"Usage
  peanut COMMAND

Commands
  encrypt  Compress and encrypt the output of a command
  decrypt  Decrypt and decompress
  help     Print this help message

  The commands can be expressed with any substring of the command's name
"
    ));
}

fn usage_encrypt(out: &mut dyn std::io::Write) {
    drop(writeln!(
        out,
        r"Usage
  peanut encrypt [OPTIONS]

Option
  -k,--key <KEY> Specify the key to be used for encryption
                 By default, it takes the value from the environment variable PEANUT_KEY
  -f,--full      Don't attempt to stream but load everything into memory
                 If enabled, the decryption cannot be streamed
  -h,--help      Prints this help message

Key
  pwd:<KEY>      Use the key as is passed. Not recommended
  hex:<KEY>      Interpret the key as a hexadecimal string representation of the bytes
  b64:<KEY>      Interpret the key as a base64 encoded representation of the bytes
  src:<PATH>     Read the contents of the path to retrieve the bytes
"
    ));
}

fn usage_decrypt(out: &mut dyn std::io::Write) {
    drop(writeln!(
        out,
        r"Usage
  peanut decrypt [OPTIONS]

Option
  -k,--key <KEY> Specify the key to be used for decryption
                 By default, it takes the value from the environment variable PEANUT_KEY
  -f,--full      Don't attempt to stream but load everything into memory
                 Should only be enabled if the encryption was also not streamed
  -h,--help      Prints this help message

Key
  pwd:<KEY>      Use the key as is passed. Not recommended
  hex:<KEY>      Interpret the key as a hexadecimal string representation of the bytes
  b64:<KEY>      Interpret the key as a base64 encoded representation of the bytes
  src:<PATH>     Read the contents of the path to retrieve the bytes
"
    ));
}

#[derive(Debug)]
pub enum Command {
    Encrypt(Mode),
    Decrypt(Mode),
}

#[derive(Debug)]
pub enum Mode {
    Stream(Key),
    Full(Key),
}

#[derive(Debug)]
pub enum Key {
    Raw([u8; 32]),
    Pwd(String),
}

pub fn parse() -> anyhow::Result<Command> {
    let mut args = std::env::args_os();

    let Some(command) = args.nth(1) else {
        arg_error!("Command missing");
    };

    let command = command.to_string_lossy();

    if "encrypt".starts_with(command.as_ref()) {
        parse_args(args, usage_encrypt).map(Command::Encrypt)
    } else if "decrypt".starts_with(command.as_ref()) {
        parse_args(args, usage_decrypt).map(Command::Decrypt)
    } else if "help".starts_with(command.as_ref()) {
        usage(std::io::stdout());
        std::process::exit(0);
    } else {
        arg_error!(usage, "Unrecognized command: {command}");
    }
}

fn parse_args<Help>(args: std::env::ArgsOs, help: Help) -> anyhow::Result<Mode>
where
    Help: Copy + Fn(&mut dyn std::io::Write),
{
    let (key, full) = get_key_arg(args, help);
    let key = get_key(key, help)?;

    if full {
        Ok(Mode::Full(key))
    } else {
        Ok(Mode::Stream(key))
    }
}

fn get_key_arg<Help>(mut args: std::env::ArgsOs, help: Help) -> (std::ffi::OsString, bool)
where
    Help: Fn(&mut dyn std::io::Write),
{
    let mut key = None;
    let mut full = false;
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            help(&mut std::io::stdout());
            std::process::exit(0);
        } else if arg == "-k" || arg == "--key" {
            if key.is_some() {
                arg_error!(help, "Key defined multiple times");
            }
            match args.next() {
                None => arg_error!(help, "Missing value for the key"),
                value => key = value,
            }
        } else if arg == "-f" || arg == "--full" {
            full = true;
        } else {
            arg_error!(help, "Unkown argument: {}", arg.to_string_lossy());
        }
    }

    let Some(key) = key.or_else(|| std::env::var_os("PEANUT_KEY")) else {
        arg_error!(help, "Missing key");
    };

    (key, full)
}

fn get_key<Help>(arg: std::ffi::OsString, help: Help) -> anyhow::Result<Key>
where
    Help: Copy + Fn(&mut dyn std::io::Write),
{
    use anyhow::Context;
    use std::io::Read;

    let arg = arg
        .into_string()
        .map_err(|_| anyhow::anyhow!("The key parameter is not valid UTF8"))?;

    let key = if let Some(key) = arg.strip_prefix("pwd:") {
        return Ok(Key::Pwd(String::from(key)));
    } else if let Some(key) = arg.strip_prefix("hex:") {
        hex::decode(key).context("Not a valid hex string")?
    } else if let Some(key) = arg.strip_prefix("b64:") {
        base64::engine::Engine::decode(&base64::engine::general_purpose::STANDARD, key)
            .context("Not a valid base64 string")?
    } else if let Some(key) = arg.strip_prefix("src:") {
        let path = std::path::PathBuf::from(key);
        if !path.exists() {
            anyhow::bail!("The key file does not exist");
        }

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .context("Could not open the key file")?;

        let mut buf = super::make_buffer::<32>();

        file.read_exact(&mut buf)?;
        if file.read(&mut [0]).is_ok() {
            Vec::new()
        } else {
            buf.into()
        }
    } else {
        arg_error!(help, "Unrecognized key format");
    };

    if key.len() != 32 {
        anyhow::bail!("Key provided is not 256 bits");
    }
    let mut out = [0; 32];
    out.copy_from_slice(&key);

    Ok(Key::Raw(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str() {
        let Ok(Key::Pwd(key)) = get_key("pwd:yooo".into(), usage_decrypt) else {
            panic!()
        };
        assert_eq!(key, "yooo");
    }

    #[test]
    fn test_hex() {
        let Ok(Key::Raw(key)) = get_key(
            "hex:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F".into(),
            usage_decrypt,
        ) else {
            panic!()
        };
        assert_eq!(
            key,
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
    }

    #[test]
    fn test_hex_invalid() {
        let err = get_key(
            "hex:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1".into(),
            usage_decrypt,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(err, "Not a valid hex string");
    }

    #[test]
    fn test_hex_short() {
        let err = get_key(
            "hex:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E".into(),
            usage_decrypt,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(err, "Key provided is not 256 bits");
    }

    #[test]
    fn test_b64() {
        let Ok(Key::Raw(key)) = get_key(
            "b64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
            usage_decrypt,
        ) else {
            panic!()
        };
        assert_eq!(
            key,
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
    }

    #[test]
    fn test_b64_invalid() {
        let err = get_key(
            "b64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into(),
            usage_decrypt,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(err, "Not a valid base64 string");
    }

    #[test]
    fn test_b64_short() {
        let err = get_key(
            "b64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==".into(),
            usage_decrypt,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(err, "Key provided is not 256 bits");
    }
}
