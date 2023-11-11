pub fn parse() -> Args {
    <Parser as clap::Parser>::parse().into()
}

#[derive(Debug)]
pub struct Args {
    pub verbosity: log::LevelFilter,
    pub mode: Mode,
    pub command: Vec<std::ffi::OsString>,
}

#[derive(Debug, clap::Parser)]
struct Parser {
    #[arg(short, action = clap::ArgAction::Count)]
    verbosity: u8,

    #[arg(short, long, value_enum, default_value_t = Mode::Both)]
    mode: Mode,

    command: Vec<std::ffi::OsString>,
}

impl From<Parser> for Args {
    fn from(value: Parser) -> Self {
        let verbosity = match value.verbosity {
            0 => log::LevelFilter::Error,
            1 => log::LevelFilter::Warn,
            2 => log::LevelFilter::Info,
            3 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        };

        Self {
            verbosity,
            mode: value.mode,
            command: value.command,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum Mode {
    Stdout,
    Stderr,
    Both,
}
