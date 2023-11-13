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
        r#"Usage
  peanut COMMAND

Commands
  encrypt  Compress and encrypt the output of a command
  decrypt  Decrypt and decompress
  help     Pring this help message

  The commands can be expressed with any substring of the command's name
"#
    ));
}

fn usage_encrypt(out: &mut dyn std::io::Write) {
    drop(writeln!(
        out,
        r#"Usage
  peanut encrypt [OPTIONS]

Option
  -k,--key <KEY> Specify the key to be used for encryption
                 By default, it takes the value from the environment variable PEANUT_KEY
  -h,--help      Prints this help message

Key
  raw:<KEY>      Use the key as is passed. Not recommended
  hex:<KEY>      Interpret the key as a hexadecimal string representation of the bytes
  b64:<KEY>      Interpret the key as a base64 encoded representation of the bytes
  src:<PATH>     Read the contents of the path to retrieve the bytes
"#
    ));
}

fn usage_decrypt(out: &mut dyn std::io::Write) {
    drop(writeln!(
        out,
        r#"Usage
  peanut decrypt [OPTIONS]

Option
  -k,--key <KEY> Specify the key to be used for decryption
                 By default, it takes the value from the environment variable PEANUT_KEY
  -h,--help      Prints this help message

Key
  raw:<KEY>      Use the key as is passed. Not recommended
  hex:<KEY>      Interpret the key as a hexadecimal string representation of the bytes
  b64:<KEY>      Interpret the key as a base64 encoded representation of the bytes
  src:<PATH>     Read the contents of the path to retrieve the bytes
"#
    ));
}

pub enum Command {
    Encrypt([u8; 32]),
    Decrypt([u8; 32]),
}

pub fn parse() -> anyhow::Result<Command> {
    let mut args = std::env::args_os();

    let Some(command) = args.nth(1) else {
        arg_error!("Command missing");
    };

    let command = command.to_string_lossy();

    if "encrypt".starts_with(command.as_ref()) {
        get_key(args, usage_encrypt).map(Command::Encrypt)
    } else if "decrypt".starts_with(command.as_ref()) {
        get_key(args, usage_decrypt).map(Command::Decrypt)
    } else if "help".starts_with(command.as_ref()) {
        usage(std::io::stdout());
        std::process::exit(0);
    } else {
        arg_error!(usage, "Unrecognized command: {command}");
    }
}

fn get_key<Help>(args: std::env::ArgsOs, help: Help) -> anyhow::Result<[u8; 32]>
where
    Help: Copy + Fn(&mut dyn std::io::Write),
{
    use anyhow::Context;
    use sha2::Digest;
    use std::io::Read;

    let arg = get_key_arg(args, help)
        .into_string()
        .map_err(|_| anyhow::anyhow!("The key parameter is not valid UTF8"))?;

    let mut hasher = sha2::Sha256::new();
    if let Some(key) = arg.strip_prefix("raw:") {
        hasher.update(key.as_bytes());
    } else if let Some(key) = arg.strip_prefix("hex:") {
        let bytes = hex::decode(key).context("Not a valid hex string")?;
        hasher.update(bytes);
    } else if let Some(key) = arg.strip_prefix("b64:") {
        let bytes = base64::engine::Engine::decode(&base64::engine::general_purpose::STANDARD, key)
            .context("Not a valid base64 string")?;
        hasher.update(bytes);
    } else if let Some(key) = arg.strip_prefix("src:") {
        const BUF_LEN: usize = super::BUF_LEN;

        let path = std::path::PathBuf::from(key);
        if !path.exists() {
            anyhow::bail!("The key file does not exist");
        }

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .context("Could not open the key file")?;

        let mut buf = super::make_buffer::<BUF_LEN>();

        loop {
            let bytes = file
                .read(&mut buf)
                .context("Error while reading from key file")?;

            if bytes == 0 {
                break;
            }

            hasher.update(&buf[..bytes]);
        }
    } else {
        arg_error!(help, "Unrecognized key format");
    }

    Ok(hasher.finalize().into())
}

fn get_key_arg<Help>(mut args: std::env::ArgsOs, help: Help) -> std::ffi::OsString
where
    Help: Fn(&mut dyn std::io::Write),
{
    if let Some(option) = args.next() {
        if option == "-h" || option == "--help" {
            help(&mut std::io::stdout());
            std::process::exit(0);
        }

        if option == "-k" || option == "--key" {
            let Some(key) = args.next() else {
                arg_error!(help, "Missing value for the key");
            };

            if args.next().is_some() {
                arg_error!(help, "Too many arguments");
            }

            key
        } else {
            arg_error!(help, "Unkown argument: {}", option.to_string_lossy());
        }
    } else {
        let Some(key) = std::env::var_os("PEANUT_KEY") else {
            arg_error!(help, "Missing key");
        };

        key
    }
}
