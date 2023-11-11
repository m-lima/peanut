#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    Stdout,
    Stderr,
    Both,
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
"#
    ));
}

pub enum Command {
    Encrypt(std::ffi::OsString),
    Decrypt(std::ffi::OsString),
}

pub fn parse() -> Command {
    let mut args = std::env::args_os();

    let Some(command) = args.nth(1) else {
        error!("Command missing");
        eprintln!();
        usage(std::io::stderr());
        std::process::exit(1);
    };

    let command = command.to_string_lossy();

    if "encrypt".starts_with(command.as_ref()) {
        let key = get_key(args, usage_encrypt);
        Command::Encrypt(key)
    } else if "decrypt".starts_with(command.as_ref()) {
        let key = get_key(args, usage_decrypt);
        Command::Decrypt(key)
    } else if "help".starts_with(command.as_ref()) {
        usage(std::io::stdout());
        std::process::exit(0);
    } else {
        error!("Unrecognized command: {command}");
        eprintln!();
        usage(std::io::stderr());
        std::process::exit(1);
    }
}

fn get_key<Help>(mut args: std::env::ArgsOs, help: Help) -> std::ffi::OsString
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
                error!("Missing value for the key");
                eprintln!();
                help(&mut std::io::stderr());
                std::process::exit(1);
            };

            if args.next().is_some() {
                error!("Too many arguments");
                eprintln!();
                help(&mut std::io::stderr());
                std::process::exit(1);
            }

            key
        } else {
            error!("Unkown argument: {}", option.to_string_lossy());
            eprintln!();
            help(&mut std::io::stderr());
            std::process::exit(1);
        }
    } else {
        let Some(key) = std::env::var_os("PEANUT_KEY") else {
            error!("Missing key");
            eprintln!();
            help(&mut std::io::stderr());
            std::process::exit(1);
        };

        key
    }
}
