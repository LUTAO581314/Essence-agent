use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};
use essence_core::ControlPlane;

#[path = "essence_cli/agency_templates.rs"]
mod agency_templates;
#[path = "essence_cli/agent_profile.rs"]
mod agent_profile;
#[path = "essence_cli/args.rs"]
mod args;
#[path = "essence_cli/chat.rs"]
mod chat;
#[path = "essence_cli/commands.rs"]
mod commands;
#[path = "essence_cli/model_config.rs"]
mod model_config;
#[path = "essence_cli/pixel_ui.rs"]
mod pixel_ui;
#[path = "essence_cli/setup.rs"]
mod setup;
#[path = "essence_cli/support.rs"]
mod support;
#[path = "essence_cli/workspace_view.rs"]
mod workspace_view;

#[cfg(test)]
#[path = "essence_cli/tests.rs"]
mod tests;

use args::{
    Cli, CliCompletionShell, Command, CompletionArgs, CompletionCommand, CompletionGenerateArgs,
    CompletionInstallArgs,
};
use support::{CliError, OutputMode, OutputModeConfig};

fn main() -> ExitCode {
    if root_version_requested() {
        println!("essence {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return exit_clap_error(error),
    };
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

fn root_version_requested() -> bool {
    let args = std::env::args().collect::<Vec<_>>();
    args.len() == 2 && matches!(args[1].as_str(), "-v" | "--version")
}

fn exit_clap_error(error: clap::Error) -> ExitCode {
    let code = error.exit_code();
    let is_usage_error = code != 0;
    let _ = error.print();
    if is_usage_error {
        let _ = writeln!(
            io::stderr().lock(),
            "\nTry one of:\n  essence setup --save\n  essence chat\n  essence session create --cwd . --json\n\nUse `essence --help` for all commands."
        );
    }
    ExitCode::from(code as u8)
}

fn execute(cli: Cli, writer: &mut impl Write) -> Result<(), CliError> {
    let root = cli.root.clone();
    let stored_theme = commands::configured_theme(&root);
    let output = OutputMode::new(OutputModeConfig {
        output: cli.output,
        json: cli.json,
        quiet: cli.quiet,
        verbose: cli.verbose,
        dry_run: cli.dry_run,
        requested_theme: cli.theme,
        stored_theme,
        no_color: cli.no_color,
        stdout_is_terminal: io::stdout().is_terminal(),
    });
    let control = ControlPlane::new(&root);
    match cli.command {
        Command::Setup(mut args) => {
            if output.no_color {
                args.no_color = true;
            }
            let requested_save = args.save;
            if output.dry_run {
                args.save = false;
            }
            setup::execute_setup(&control, args, writer)?;
            if output.dry_run && requested_save {
                writeln!(writer, "dry run: no setup files written")?;
            }
            Ok(())
        }
        Command::Ask(args) => chat::execute_ask(&control, args, output, writer),
        Command::Chat(args) => {
            if output.dry_run {
                return Err(CliError::Usage(
                    "chat does not support --dry-run; use scriptable data commands to preview ledger writes".to_string(),
                ));
            }
            if let Some(reason) = non_interactive_reason() {
                return Err(CliError::NonInteractive(format!(
                    "{reason}; `essence chat` requires an interactive terminal"
                )));
            }
            let stdin = io::stdin();
            let mut reader = stdin.lock();
            let mut args = args;
            if output.no_color {
                args.no_color = true;
            }
            chat::execute_chat(&control, args, &mut reader, writer)
        }
        Command::Session(args) => commands::execute_session(&control, args, output, writer),
        Command::Message(args) => commands::execute_message(&control, args, output, writer),
        Command::Run(args) => commands::execute_run(&control, args, output, writer),
        Command::Events(args) => commands::execute_events(&control, args, output, writer),
        Command::Tool(args) => commands::execute_tool(&control, args, output, writer),
        Command::Approval(args) => commands::execute_approval(&control, args, output, writer),
        Command::Agent(args) => commands::execute_agent(&control, args, output, writer),
        Command::Task(args) => commands::execute_task(&control, args, output, writer),
        Command::Artifact(args) => commands::execute_artifact(&control, args, output, writer),
        Command::Memory(args) => commands::execute_memory(&control, args, output, writer),
        Command::Subagent(args) => commands::execute_subagent(&control, args, output, writer),
        Command::Snapshot(args) => commands::execute_snapshot(&control, args, output, writer),
        Command::Workspace(mut args) => {
            if output.no_color {
                match &mut args.command {
                    args::WorkspaceCommand::Dashboard(args) => args.no_color = true,
                    args::WorkspaceCommand::Watch(args) => args.no_color = true,
                }
            }
            workspace_view::execute_workspace(&control, args, writer)
        }
        Command::Plugin(args) => commands::execute_plugin(&control, args, output, writer),
        Command::Mcp(args) => commands::execute_mcp(&control, args, output, writer),
        Command::Harness(args) => commands::execute_harness(&control, args, output, writer),
        Command::Theme(args) => commands::execute_theme(&control, args, output, writer),
        Command::Config(args) => commands::execute_config(&control, args, output, writer),
        Command::Doctor(args) => commands::execute_doctor(&control, args, output, writer),
        Command::Completion(args) => execute_completion(args, output, writer),
    }
}

fn execute_completion(
    args: CompletionArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        Some(CompletionCommand::Generate(CompletionGenerateArgs { shell })) => {
            write_completion(shell, writer);
            Ok(())
        }
        Some(CompletionCommand::Install(args)) => install_completion(args, output, writer),
        None => {
            let shell = args.shell.ok_or_else(|| {
                CliError::Usage(
                    "completion requires a shell, `completion generate <shell>`, or `completion install <shell>`"
                        .to_string(),
                )
            })?;
            write_completion(shell, writer);
            Ok(())
        }
    }
}

fn write_completion(shell: CliCompletionShell, writer: &mut impl Write) {
    let mut command = Cli::command();
    generate(completion_shell(shell), &mut command, "essence", writer);
}

fn install_completion(
    args: CompletionInstallArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let path = completion_install_path(args.shell, args.dir)?;
    let mut script = Vec::new();
    write_completion(args.shell, &mut script);

    if output.dry_run {
        writeln!(writer, "dry run: would write {}", path.display())?;
        writeln!(writer, "{}", completion_install_hint(args.shell, &path))?;
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, script)?;
    writeln!(writer, "installed completion {}", path.display())?;
    writeln!(writer, "{}", completion_install_hint(args.shell, &path))?;
    Ok(())
}

fn completion_install_path(
    shell: CliCompletionShell,
    dir: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    let base = match dir {
        Some(dir) => dir,
        None => default_completion_dir(shell)?,
    };
    Ok(base.join(completion_file_name(shell)))
}

fn default_completion_dir(shell: CliCompletionShell) -> Result<PathBuf, CliError> {
    let home = home_dir()?;
    Ok(match shell {
        CliCompletionShell::Bash => home.join(".local/share/bash-completion/completions"),
        CliCompletionShell::Zsh => home.join(".zfunc"),
        CliCompletionShell::Fish => home.join(".config/fish/completions"),
        CliCompletionShell::PowerShell => home.join("Documents").join("PowerShell"),
        CliCompletionShell::Elvish => home.join(".elvish/lib"),
    })
}

fn home_dir() -> Result<PathBuf, CliError> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::Usage("could not determine home directory; pass --dir".to_string())
        })
}

fn completion_file_name(shell: CliCompletionShell) -> &'static str {
    match shell {
        CliCompletionShell::Bash => "essence",
        CliCompletionShell::Zsh => "_essence",
        CliCompletionShell::Fish => "essence.fish",
        CliCompletionShell::PowerShell => "essence.ps1",
        CliCompletionShell::Elvish => "essence-completions.elv",
    }
}

fn completion_install_hint(shell: CliCompletionShell, path: &std::path::Path) -> String {
    match shell {
        CliCompletionShell::Bash => {
            "restart your shell or source your bash completion setup".to_string()
        }
        CliCompletionShell::Zsh => format!(
            "ensure `{}` is in fpath, then run `autoload -Uz compinit && compinit`",
            path.parent()
                .map(|parent| parent.display().to_string())
                .unwrap_or_else(|| ".".to_string())
        ),
        CliCompletionShell::Fish => {
            "fish loads completions from its completions directory automatically".to_string()
        }
        CliCompletionShell::PowerShell => format!(
            "dot-source from your PowerShell profile: . '{}'",
            path.display()
        ),
        CliCompletionShell::Elvish => {
            "add the installed file to your Elvish startup as needed".to_string()
        }
    }
}

fn completion_shell(shell: CliCompletionShell) -> Shell {
    match shell {
        CliCompletionShell::Bash => Shell::Bash,
        CliCompletionShell::Zsh => Shell::Zsh,
        CliCompletionShell::Fish => Shell::Fish,
        CliCompletionShell::PowerShell => Shell::PowerShell,
        CliCompletionShell::Elvish => Shell::Elvish,
    }
}

fn non_interactive_reason() -> Option<String> {
    let mut reasons = Vec::new();
    if !io::stdin().is_terminal() {
        reasons.push("stdin is not a terminal".to_string());
    }
    if !io::stdout().is_terminal() {
        reasons.push("stdout is not a terminal".to_string());
    }
    for name in ["CI", "GITHUB_ACTIONS", "TF_BUILD", "BUILD_BUILDID"] {
        if std::env::var_os(name).is_some() {
            reasons.push(format!("{name} is set"));
            break;
        }
    }
    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join(", "))
    }
}
