mod args;
mod command;
mod list;

#[cfg(not(target_family = "unix"))]
compile_error!("Peanut only supports Unix-like systems");

fn init_logger(level: log::LevelFilter) -> Result<(), log::SetLoggerError> {
    simplelog::TermLogger::init(
        level,
        match simplelog::ConfigBuilder::default()
            .set_thread_level(log::LevelFilter::Trace)
            .set_time_offset_to_local()
        {
            Ok(b) => b.set_time_format_custom(simplelog::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second]"
            )),
            Err(b) => b.set_time_format_custom(simplelog::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
            )),
        }
        .build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    log::info!("Log level set to {level}");
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args = args::parse();

    if let Err(err) = init_logger(args.verbosity) {
        eprintln!("[31mError:[m {err}");
        return std::process::ExitCode::FAILURE;
    }

    if let Err(err) = match args.command {
        args::Command::List(list) => list::run(list),
    } {
        log::error!("{err}");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
