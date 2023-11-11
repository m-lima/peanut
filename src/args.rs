macro_rules! arg_error {
    ($($arg:tt)*) => {{
        error!($($arg)*);
        eprintln!();
        usage(std::io::stderr());
        std::process::exit(1);
    }};
}

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
  peanut [OPTIONS] [--] <COMMAND>

Options
  -m,--mode <MODE> Specify which output to capture from the child process
                   If an output is not captured, it will be echoed back on stdout
                   Possible values: [stdout, stderr, both]
                   Default: stdout
  -h,--help        Prints this help message
"#
    ));
}

#[derive(Debug)]
pub struct Args {
    pub mode: Mode,
    pub command: std::ffi::OsString,
    pub args: std::env::ArgsOs,
}

pub fn parse() -> Args {
    let mut args = std::env::args_os();
    let mut mode = None;

    let _ = args.next();
    let command = loop {
        let Some(next) = args.next() else {
            break None;
        };

        if next == "--" {
            break args.next();
        }

        if next == "-h" || next == "--help" {
            usage(std::io::stdout());
            std::process::exit(0);
        }

        if next == "-m" || next == "--mode" {
            let Some(mut mode_arg) = args.next() else {
                arg_error!("Expected a mode to be specified");
            };

            if mode.is_some() {
                arg_error!("Mode was specified more than once");
            }

            mode_arg.make_ascii_lowercase();

            if mode_arg == "stdout" {
                mode = Some(Mode::Stdout);
                continue;
            } else if mode_arg == "stderr" {
                mode = Some(Mode::Stderr);
                continue;
            } else if mode_arg == "both" {
                mode = Some(Mode::Both);
                continue;
            }

            arg_error!("Invalid mode: {}", mode_arg.to_string_lossy());
        }

        break Some(next);
    };

    let Some(command) = command else {
        arg_error!("Nothing to execute");
    };

    Args {
        mode: mode.unwrap_or(Mode::Stdout),
        command,
        args,
    }
}
