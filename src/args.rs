pub fn parse() -> Args {
    <Parser as clap::Parser>::parse().into()
}

#[derive(Debug)]
pub struct Args {
    pub verbosity: log::LevelFilter,
    pub command: Command,
}

#[derive(Debug, clap::Parser)]
struct Parser {
    #[arg(short, global = true, action = clap::ArgAction::Count)]
    verbosity: u8,

    #[command(subcommand)]
    command: Command,
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
            command: value.command,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    List(List),
}

#[derive(Debug, clap::Args)]
pub struct List {
    #[arg(short, long, global = true, default_value = "/.snapshots", value_parser = clap::builder::TypedValueParser::try_map(clap::builder::OsStringValueParser::new(), parse_dir))]
    pub snapshots: std::path::PathBuf,

    #[arg(short, long, global = true)]
    pub use_sudo: bool,
}

fn parse_dir(input: std::ffi::OsString) -> anyhow::Result<std::path::PathBuf> {
    let path = std::path::PathBuf::from(input);

    if !path.exists() {
        Err(anyhow::anyhow!("Path does not exist"))
    } else if !path.is_dir() {
        Err(anyhow::anyhow!("Path is not a directory"))
    } else {
        std::fs::canonicalize(path).map_err(Into::into)
    }
}
