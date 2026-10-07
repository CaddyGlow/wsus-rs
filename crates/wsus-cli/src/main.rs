use clap::Parser;
use std::process::ExitCode;
use wsus_cli::{
    app,
    cli::Cli,
    logging::{self, LogOptions},
    output::render_text,
    redact::sanitize,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (config, config_path) = match app::load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", sanitize(&format!("{e:#}")));
            return ExitCode::from(1);
        }
    };
    let options = LogOptions {
        level: config.logging.level.clone(),
        json: config.logging.format == "json",
        verbose: cli.verbose,
        trace_file: cli.trace_file.clone(),
    };
    if let Err(e) = logging::init(&options) {
        eprintln!("error: {}", sanitize(&format!("{e:#}")));
        return ExitCode::from(1);
    }
    let result = if app::is_diagnostics(&cli) {
        app::run_diagnostics(&cli, &config)
    } else {
        app::run(&cli, &config, &config_path)
    };
    match result {
        Ok(output) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output.value).unwrap_or_default()
                );
            } else {
                print!("{}", render_text(&output.value));
            }
            if output.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(e) => {
            eprintln!("error: {}", sanitize(&format!("{e:#}")));
            ExitCode::from(1)
        }
    }
}
