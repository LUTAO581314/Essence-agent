use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use essence_core::ControlPlane;

#[path = "essence_cli/args.rs"]
mod args;
#[path = "essence_cli/chat.rs"]
mod chat;
#[path = "essence_cli/commands.rs"]
mod commands;
#[path = "essence_cli/support.rs"]
mod support;
#[path = "essence_cli/workspace_view.rs"]
mod workspace_view;

#[cfg(test)]
#[path = "essence_cli/tests.rs"]
mod tests;

use args::{Cli, Command};
use support::CliError;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let stdout = io::stdout();
    let mut writer = stdout.lock();

    match execute(cli, &mut writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli, writer: &mut impl Write) -> Result<(), CliError> {
    let control = ControlPlane::new(&cli.root);
    match cli.command {
        Command::Chat(args) => {
            let stdin = io::stdin();
            let mut reader = stdin.lock();
            chat::execute_chat(&control, args, &mut reader, writer)
        }
        Command::Session(args) => commands::execute_session(&control, args, writer),
        Command::Message(args) => commands::execute_message(&control, args, writer),
        Command::Events(args) => commands::execute_events(&control, args, writer),
        Command::Approval(args) => commands::execute_approval(&control, args, writer),
        Command::Agent(args) => commands::execute_agent(&control, args, writer),
        Command::Task(args) => commands::execute_task(&control, args, writer),
        Command::Workspace(args) => workspace_view::execute_workspace(&control, args, writer),
    }
}
