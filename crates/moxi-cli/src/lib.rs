use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use moxi_contracts::{RiskLevel, ShellAdapterManifest, ShellSurface};
use moxi_runtime::{ResumeBlocker, RuntimeEventFeedSnapshot, RuntimeQuerySnapshot};
use moxi_shells::{adapter_manifest, ShellController, ShellRequestDraft};
use ratatui::{
    backend::{CrosstermBackend, TestBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use std::{
    env, fs,
    io::{BufRead, Stdout, Write},
    thread,
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("missing command; try `moxi-cli help`")]
    MissingCommand,
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("missing value for {0}")]
    MissingValue(&'static str),
    #[error("missing required option: {0}")]
    MissingRequired(&'static str),
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    #[error("invalid risk level: {0}")]
    InvalidRisk(String),
    #[error("invalid shell surface: {0}")]
    InvalidSurface(String),
    #[error("invalid status render limit: {0}")]
    InvalidLimit(String),
    #[error("invalid watch tick count: {0}")]
    InvalidWatchTicks(String),
    #[error("invalid watch interval milliseconds: {0}")]
    InvalidWatchInterval(String),
    #[error("invalid tui dimension for {flag}: {value}")]
    InvalidTuiDimension { flag: &'static str, value: String },
    #[error("invalid tui key token: {0}")]
    InvalidTuiKey(String),
    #[error("invalid tui poll milliseconds: {0}")]
    InvalidTuiPoll(String),
    #[error("runtime projection graph mismatch: expected {expected}, got {actual}")]
    GraphMismatch { expected: String, actual: String },
    #[error("status input mode conflict; choose only one of --feed or --query")]
    StatusInputConflict,
    #[error("unterminated quoted string in REPL input")]
    UnterminatedQuote,
    #[error("shell error: {0}")]
    Shell(#[from] moxi_shells::ShellError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type CliResult<T> = Result<T, CliError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    PrettyJson,
    Text,
    Panel,
}

impl OutputFormat {
    fn is_pretty(self) -> bool {
        matches!(self, Self::PrettyJson)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmitOptions {
    tenant_id: String,
    user_id: String,
    workspace_root: String,
    goal: String,
    requested_capabilities: Vec<String>,
    risk_level: RiskLevel,
    session_id: Option<String>,
    request_id: Option<String>,
    source_ref: Option<String>,
    format: OutputFormat,
}

impl AdmitOptions {
    fn into_draft(self) -> ShellRequestDraft {
        let mut draft = ShellRequestDraft::cli_readonly(
            self.tenant_id,
            self.user_id,
            self.workspace_root,
            self.goal,
        );
        if !self.requested_capabilities.is_empty() {
            draft.requested_capabilities = self.requested_capabilities;
        }
        draft.risk_level = self.risk_level;
        draft.session_id = self.session_id;
        draft.request_id = self.request_id;
        draft.source_ref = self.source_ref;
        draft
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestOptions {
    surface: ShellSurface,
    format: OutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundaryOptions {
    surface: ShellSurface,
    format: OutputFormat,
}

#[derive(Debug, serde::Serialize)]
struct BoundaryReport {
    surface: ShellSurface,
    adapter_manifest: ShellAdapterManifest,
    supported_commands: Vec<&'static str>,
    forbidden_commands: Vec<&'static str>,
    trust_boundaries: Vec<&'static str>,
    cannot_execute_directly: bool,
    cannot_authorize: bool,
    cannot_issue_tickets: bool,
    cannot_verify: bool,
    cannot_commit_ledger: bool,
    note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatusOptions {
    surface: ShellSurface,
    profile_id: String,
    graph_id: Option<String>,
    input_path: Option<String>,
    input_mode: StatusInputMode,
    format: OutputFormat,
    render_limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchOptions {
    status: StatusOptions,
    ticks: usize,
    interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiOptions {
    status: StatusOptions,
    width: u16,
    height: u16,
    keys: Vec<TuiKey>,
    interactive: bool,
    poll_interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiState {
    active_pane: TuiPane,
    filter: Option<String>,
    selected_task_index: usize,
    refresh_count: usize,
    should_quit: bool,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            active_pane: TuiPane::Overview,
            filter: None,
            selected_task_index: 0,
            refresh_count: 0,
            should_quit: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiPane {
    Overview,
    Graph,
    Tasks,
    Approvals,
    Boundary,
    Keys,
}

impl TuiPane {
    fn next(self) -> Self {
        match self {
            Self::Overview => Self::Graph,
            Self::Graph => Self::Tasks,
            Self::Tasks => Self::Approvals,
            Self::Approvals => Self::Boundary,
            Self::Boundary => Self::Keys,
            Self::Keys => Self::Overview,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Graph => "Graph",
            Self::Tasks => "Tasks",
            Self::Approvals => "Approvals",
            Self::Boundary => "Boundary",
            Self::Keys => "Keys",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TuiKey {
    Tab,
    Focus(TuiPane),
    MoveTaskDown,
    MoveTaskUp,
    Refresh,
    Quit,
    Filter(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusInputMode {
    EventFeed,
    QuerySnapshot,
}

pub fn run<I, S, W>(args: I, mut writer: W) -> CliResult<i32>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    W: Write,
{
    let args = normalize_args(args);
    run_command(&args, &mut writer)
}

pub fn run_with_io<I, S, R, W>(args: I, reader: R, mut writer: W) -> CliResult<i32>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    R: BufRead,
    W: Write,
{
    let args = normalize_args(args);
    if args.first().is_some_and(|command| command == "repl") {
        run_repl(reader, writer)
    } else {
        run_command_with_optional_reader(&args, Some(reader), &mut writer)
    }
}

fn run_command(args: &[String], writer: &mut impl Write) -> CliResult<i32> {
    run_command_with_optional_reader(args, None::<&[u8]>, writer)
}

fn run_command_with_optional_reader<R>(
    args: &[String],
    reader: Option<R>,
    writer: &mut impl Write,
) -> CliResult<i32>
where
    R: BufRead,
{
    let Some((command, rest)) = args.split_first() else {
        return Err(CliError::MissingCommand);
    };

    match command.as_str() {
        "admit" => {
            let options = parse_admit(rest)?;
            let format = options.format;
            let admission = ShellController::default().admit_shell_request(options.into_draft())?;
            write_json(writer, &admission, format)?;
        }
        "manifest" => {
            let options = parse_manifest(rest)?;
            let manifest = adapter_manifest(options.surface);
            write_json(writer, &manifest, options.format)?;
        }
        "boundary" => {
            let options = parse_boundary(rest)?;
            let format = options.format;
            let report = boundary_report(options.surface);
            if matches!(format, OutputFormat::Text) {
                write_boundary_text(writer, &report)?;
            } else {
                write_json(writer, &report, format)?;
            }
        }
        "status" => {
            let options = parse_status(rest)?;
            let format = options.format;
            let render_limit = options.render_limit;
            let projection = project_status(options, reader)?;
            render_status_projection(writer, &projection, format, render_limit)?;
        }
        "watch" => {
            let options = parse_watch(rest)?;
            run_watch(options, writer)?;
        }
        "tui" => {
            let options = parse_tui(rest)?;
            run_tui(options, writer)?;
        }
        "help" | "--help" | "-h" => {
            writeln!(writer, "{}", help_text())?;
        }
        unknown => return Err(CliError::UnknownCommand(unknown.to_owned())),
    }

    Ok(0)
}

fn project_status<R>(
    options: StatusOptions,
    reader: Option<R>,
) -> CliResult<moxi_shells::ShellProjection>
where
    R: BufRead,
{
    let surface = options.surface;
    let profile_id = options.profile_id.clone();
    let graph_id = options.graph_id.clone();
    let input_mode = options.input_mode;
    let text = read_status_input(options, reader)?;
    match input_mode {
        StatusInputMode::EventFeed => {
            let snapshot: RuntimeEventFeedSnapshot = serde_json::from_str(&text)?;
            ensure_graph_matches(graph_id, snapshot.graph_id.as_deref())?;
            Ok(ShellController::default().project_event_feed(surface, profile_id, snapshot)?)
        }
        StatusInputMode::QuerySnapshot => {
            let snapshot: RuntimeQuerySnapshot = serde_json::from_str(&text)?;
            ensure_graph_matches(graph_id, Some(&snapshot.graph.graph_id))?;
            Ok(ShellController::default().project_query_snapshot(surface, snapshot)?)
        }
    }
}

fn render_status_projection(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    format: OutputFormat,
    render_limit: Option<usize>,
) -> CliResult<()> {
    match format {
        OutputFormat::Text => write_status_text(writer, projection, render_limit)?,
        OutputFormat::Panel => write_status_panel(writer, projection, render_limit)?,
        OutputFormat::Json | OutputFormat::PrettyJson => write_json(writer, projection, format)?,
    }
    Ok(())
}

fn run_watch(options: WatchOptions, writer: &mut impl Write) -> CliResult<()> {
    for tick in 0..options.ticks {
        let projection = project_status(options.status.clone(), None::<&[u8]>)?;
        writeln!(writer, "watch tick {}/{}", tick + 1, options.ticks)?;
        render_status_projection(
            writer,
            &projection,
            options.status.format,
            options.status.render_limit,
        )?;
        if tick + 1 < options.ticks {
            thread::sleep(options.interval);
        }
    }
    Ok(())
}

fn run_tui(options: TuiOptions, writer: &mut impl Write) -> CliResult<()> {
    let mut state = TuiState::default();
    let mut projection = project_status(options.status.clone(), None::<&[u8]>)?;
    if options.interactive {
        return run_tui_interactive(options, projection, state);
    }
    for key in &options.keys {
        apply_tui_key(&mut state, key);
        if matches!(key, TuiKey::Refresh) {
            projection = project_status(options.status.clone(), None::<&[u8]>)?;
        }
        if state.should_quit {
            break;
        }
    }
    write_tui_snapshot(writer, &projection, &state, options.width, options.height)
}

fn run_tui_interactive(
    options: TuiOptions,
    mut projection: moxi_shells::ShellProjection,
    mut state: TuiState,
) -> CliResult<()> {
    let mut stdout = std::io::stdout();
    enable_raw_mode()?;
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error.into());
    }

    let result = run_tui_interactive_inner(&options, &mut stdout, &mut projection, &mut state);

    let raw_mode_result = disable_raw_mode();
    let alternate_screen_result = execute!(stdout, LeaveAlternateScreen);

    result?;
    raw_mode_result?;
    alternate_screen_result?;
    Ok(())
}

fn run_tui_interactive_inner(
    options: &TuiOptions,
    stdout: &mut Stdout,
    projection: &mut moxi_shells::ShellProjection,
    state: &mut TuiState,
) -> CliResult<()> {
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            render_tui_snapshot(frame, area, projection, state);
        })?;
        if state.should_quit {
            break;
        }
        if event::poll(options.poll_interval)? {
            if let Event::Key(event) = event::read()? {
                if let Some(key) = tui_key_from_event(event) {
                    apply_tui_key(state, &key);
                    if matches!(key, TuiKey::Refresh) {
                        *projection = project_status(options.status.clone(), None::<&[u8]>)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn tui_key_from_event(event: KeyEvent) -> Option<TuiKey> {
    match event.code {
        KeyCode::Tab => Some(TuiKey::Tab),
        KeyCode::Down => Some(TuiKey::MoveTaskDown),
        KeyCode::Up => Some(TuiKey::MoveTaskUp),
        KeyCode::Char('?') => Some(TuiKey::Focus(TuiPane::Keys)),
        KeyCode::Char('o') | KeyCode::Char('O') => Some(TuiKey::Focus(TuiPane::Overview)),
        KeyCode::Char('g') | KeyCode::Char('G') => Some(TuiKey::Focus(TuiPane::Graph)),
        KeyCode::Char('t') | KeyCode::Char('T') => Some(TuiKey::Focus(TuiPane::Tasks)),
        KeyCode::Char('a') | KeyCode::Char('A') => Some(TuiKey::Focus(TuiPane::Approvals)),
        KeyCode::Char('b') | KeyCode::Char('B') => Some(TuiKey::Focus(TuiPane::Boundary)),
        KeyCode::Char('j') | KeyCode::Char('J') => Some(TuiKey::MoveTaskDown),
        KeyCode::Char('k') | KeyCode::Char('K') => Some(TuiKey::MoveTaskUp),
        KeyCode::Char('r') | KeyCode::Char('R') => Some(TuiKey::Refresh),
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => Some(TuiKey::Quit),
        _ => None,
    }
}

fn apply_tui_key(state: &mut TuiState, key: &TuiKey) {
    match key {
        TuiKey::Tab => state.active_pane = state.active_pane.next(),
        TuiKey::Focus(pane) => state.active_pane = *pane,
        TuiKey::MoveTaskDown => {
            state.active_pane = TuiPane::Tasks;
            state.selected_task_index = state.selected_task_index.saturating_add(1);
        }
        TuiKey::MoveTaskUp => {
            state.active_pane = TuiPane::Tasks;
            state.selected_task_index = state.selected_task_index.saturating_sub(1);
        }
        TuiKey::Refresh => state.refresh_count += 1,
        TuiKey::Quit => state.should_quit = true,
        TuiKey::Filter(value) => {
            state.filter = if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            };
            state.selected_task_index = 0;
        }
    }
}

fn read_status_input<R>(options: StatusOptions, reader: Option<R>) -> CliResult<String>
where
    R: BufRead,
{
    let text = if let Some(path) = options.input_path {
        fs::read_to_string(path)?
    } else {
        let mut reader = reader.ok_or(CliError::MissingRequired("--input or stdin"))?;
        let mut text = String::new();
        reader.read_to_string(&mut text)?;
        text
    };
    Ok(text.trim_start_matches('\u{feff}').to_owned())
}

fn ensure_graph_matches(expected: Option<String>, actual: Option<&str>) -> CliResult<()> {
    if let Some(expected) = expected {
        let actual = actual.unwrap_or("<none>");
        if actual != expected {
            return Err(CliError::GraphMismatch {
                expected,
                actual: actual.to_owned(),
            });
        }
    }
    Ok(())
}

fn run_repl<R, W>(mut reader: R, mut writer: W) -> CliResult<i32>
where
    R: BufRead,
    W: Write,
{
    writeln!(
        writer,
        "moxi-cli repl: submit/projection shell only. Type help or exit."
    )?;

    let mut line = String::new();
    loop {
        write!(writer, "moxi> ")?;
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            writeln!(writer)?;
            break;
        }

        let trimmed = line.trim().trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit") {
            writeln!(writer, "bye")?;
            break;
        }

        match tokenize_repl_line(trimmed).and_then(|args| run_command(&args, &mut writer)) {
            Ok(_) => {}
            Err(error) => writeln!(writer, "error: {error}")?,
        }
    }

    Ok(0)
}

fn normalize_args<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| looks_like_program_name(arg)) {
        args.remove(0);
    }
    args
}

fn looks_like_program_name(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(value);
    matches!(name, "moxi-cli" | "moxi-cli.exe" | "moxi" | "moxi.exe")
}

fn tokenize_repl_line(line: &str) -> CliResult<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut token_started = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quote.is_some() => {
                if matches!(chars.peek(), Some('"') | Some('\'') | Some('\\')) {
                    current.push(chars.next().unwrap());
                } else {
                    current.push(ch);
                }
                token_started = true;
            }
            '"' | '\'' => {
                if quote == Some(ch) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(ch);
                    token_started = true;
                } else {
                    current.push(ch);
                    token_started = true;
                }
            }
            ch if ch.is_whitespace() && quote.is_none() => {
                if token_started {
                    tokens.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            ch => {
                current.push(ch);
                token_started = true;
            }
        }
    }

    if quote.is_some() {
        return Err(CliError::UnterminatedQuote);
    }
    if token_started {
        tokens.push(current);
    }

    Ok(tokens)
}

fn parse_admit(args: &[String]) -> CliResult<AdmitOptions> {
    let mut tenant_id = "local".to_owned();
    let mut user_id = "local".to_owned();
    let mut workspace_root = env::current_dir()?.to_string_lossy().into_owned();
    let mut goal = None;
    let mut requested_capabilities = Vec::new();
    let mut risk_level = RiskLevel::Low;
    let mut session_id = None;
    let mut request_id = None;
    let mut source_ref = None;
    let mut format = OutputFormat::Json;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tenant" | "-t" => {
                tenant_id = value_after(args, &mut index, "--tenant")?;
            }
            "--user" | "-u" => {
                user_id = value_after(args, &mut index, "--user")?;
            }
            "--workspace" | "-w" => {
                workspace_root = value_after(args, &mut index, "--workspace")?;
            }
            "--goal" | "-g" => {
                goal = Some(value_after(args, &mut index, "--goal")?);
            }
            "--capability" | "-c" => {
                requested_capabilities.push(value_after(args, &mut index, "--capability")?);
            }
            "--risk" => {
                risk_level = parse_risk(&value_after(args, &mut index, "--risk")?)?;
            }
            "--session" => {
                session_id = Some(value_after(args, &mut index, "--session")?);
            }
            "--request-id" => {
                request_id = Some(value_after(args, &mut index, "--request-id")?);
            }
            "--source" => {
                source_ref = Some(value_after(args, &mut index, "--source")?);
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => {
                if goal.is_none() {
                    goal = Some(value.to_owned());
                } else {
                    return Err(CliError::UnknownFlag(value.to_owned()));
                }
            }
        }
        index += 1;
    }

    Ok(AdmitOptions {
        tenant_id,
        user_id,
        workspace_root,
        goal: goal.ok_or(CliError::MissingRequired("--goal"))?,
        requested_capabilities,
        risk_level,
        session_id,
        request_id,
        source_ref,
        format,
    })
}

fn parse_manifest(args: &[String]) -> CliResult<ManifestOptions> {
    let mut surface = ShellSurface::Cli;
    let mut format = OutputFormat::Json;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--surface" | "-s" => {
                surface = parse_surface(&value_after(args, &mut index, "--surface")?)?;
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(ManifestOptions { surface, format })
}

fn parse_boundary(args: &[String]) -> CliResult<BoundaryOptions> {
    let mut surface = ShellSurface::Cli;
    let mut format = OutputFormat::Json;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--surface" | "-s" => {
                surface = parse_surface(&value_after(args, &mut index, "--surface")?)?;
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            "--text" => {
                format = OutputFormat::Text;
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(BoundaryOptions { surface, format })
}

fn parse_status(args: &[String]) -> CliResult<StatusOptions> {
    parse_status_with_defaults(args, OutputFormat::Json)
}

fn parse_status_with_defaults(
    args: &[String],
    default_format: OutputFormat,
) -> CliResult<StatusOptions> {
    let mut surface = ShellSurface::Cli;
    let mut profile_id = None;
    let mut graph_id = None;
    let mut input_path = None;
    let mut input_mode = None;
    let mut format = default_format;
    let mut render_limit = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--surface" | "-s" => {
                surface = parse_surface(&value_after(args, &mut index, "--surface")?)?;
            }
            "--profile" | "--profile-id" => {
                profile_id = Some(value_after(args, &mut index, "--profile")?);
            }
            "--graph" | "--graph-id" => {
                graph_id = Some(value_after(args, &mut index, "--graph")?);
            }
            "--input" | "-i" => {
                input_path = Some(value_after(args, &mut index, "--input")?);
            }
            "--feed" | "--event-feed" => {
                if input_mode.replace(StatusInputMode::EventFeed).is_some() {
                    return Err(CliError::StatusInputConflict);
                }
            }
            "--query" | "--query-snapshot" => {
                if input_mode.replace(StatusInputMode::QuerySnapshot).is_some() {
                    return Err(CliError::StatusInputConflict);
                }
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            "--text" => {
                format = OutputFormat::Text;
            }
            "--panel" => {
                format = OutputFormat::Panel;
            }
            "--limit" => {
                let value = value_after(args, &mut index, "--limit")?;
                render_limit = Some(parse_limit(&value)?);
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(StatusOptions {
        surface,
        profile_id: profile_id.unwrap_or_else(|| default_status_profile(surface).to_owned()),
        graph_id,
        input_path,
        input_mode: input_mode.unwrap_or(StatusInputMode::EventFeed),
        format,
        render_limit,
    })
}

fn parse_watch(args: &[String]) -> CliResult<WatchOptions> {
    let mut status_args = Vec::new();
    let mut ticks = 1;
    let mut interval = Duration::from_millis(1000);
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--ticks" => {
                let value = value_after(args, &mut index, "--ticks")?;
                ticks = parse_watch_ticks(&value)?;
            }
            "--interval-ms" => {
                let value = value_after(args, &mut index, "--interval-ms")?;
                interval = Duration::from_millis(parse_watch_interval_ms(&value)?);
            }
            value => status_args.push(value.to_owned()),
        }
        index += 1;
    }

    let status = parse_status_with_defaults(&status_args, OutputFormat::Panel)?;
    if status.input_path.is_none() {
        return Err(CliError::MissingRequired("--input"));
    }

    Ok(WatchOptions {
        status,
        ticks,
        interval,
    })
}

fn parse_tui(args: &[String]) -> CliResult<TuiOptions> {
    let mut status_args = Vec::new();
    let mut width = 100;
    let mut height = 30;
    let mut keys = Vec::new();
    let mut interactive = false;
    let mut poll_interval = Duration::from_millis(250);
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--width" => {
                let value = value_after(args, &mut index, "--width")?;
                width = parse_tui_dimension("--width", &value)?;
            }
            "--height" => {
                let value = value_after(args, &mut index, "--height")?;
                height = parse_tui_dimension("--height", &value)?;
            }
            "--keys" => {
                let value = value_after(args, &mut index, "--keys")?;
                keys = parse_tui_keys(&value)?;
            }
            "--interactive" => {
                interactive = true;
            }
            "--poll-ms" => {
                let value = value_after(args, &mut index, "--poll-ms")?;
                poll_interval = Duration::from_millis(parse_tui_poll_ms(&value)?);
            }
            value => status_args.push(value.to_owned()),
        }
        index += 1;
    }

    let mut status = parse_status_with_defaults(&status_args, OutputFormat::Panel)?;
    if status.input_path.is_none() {
        return Err(CliError::MissingRequired("--input"));
    }
    status.format = OutputFormat::Panel;

    Ok(TuiOptions {
        status,
        width,
        height,
        keys,
        interactive,
        poll_interval,
    })
}

fn default_status_profile(surface: ShellSurface) -> &'static str {
    match surface {
        ShellSurface::Cli => "shell.cli.fast",
        ShellSurface::DigitalHuman => "shell.digital_human.readonly",
        ShellSurface::Ide
        | ShellSurface::Desktop
        | ShellSurface::Web
        | ShellSurface::Mobile
        | ShellSurface::Api
        | ShellSurface::Mcp => "shell.ide.readonly",
    }
}

fn value_after(args: &[String], index: &mut usize, flag: &'static str) -> CliResult<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or(CliError::MissingValue(flag))
}

fn parse_risk(value: &str) -> CliResult<RiskLevel> {
    match normalize_token(value).as_str() {
        "low" => Ok(RiskLevel::Low),
        "medium" => Ok(RiskLevel::Medium),
        "high" => Ok(RiskLevel::High),
        "critical" => Ok(RiskLevel::Critical),
        _ => Err(CliError::InvalidRisk(value.to_owned())),
    }
}

fn parse_surface(value: &str) -> CliResult<ShellSurface> {
    match normalize_token(value).as_str() {
        "cli" => Ok(ShellSurface::Cli),
        "ide" => Ok(ShellSurface::Ide),
        "desktop" => Ok(ShellSurface::Desktop),
        "web" => Ok(ShellSurface::Web),
        "mobile" => Ok(ShellSurface::Mobile),
        "api" => Ok(ShellSurface::Api),
        "mcp" | "mcpserver" | "mcp_server" => Ok(ShellSurface::Mcp),
        "digitalhuman" | "digital_human" => Ok(ShellSurface::DigitalHuman),
        _ => Err(CliError::InvalidSurface(value.to_owned())),
    }
}

fn parse_limit(value: &str) -> CliResult<usize> {
    value
        .parse::<usize>()
        .map_err(|_| CliError::InvalidLimit(value.to_owned()))
}

fn parse_watch_ticks(value: &str) -> CliResult<usize> {
    let ticks = value
        .parse::<usize>()
        .map_err(|_| CliError::InvalidWatchTicks(value.to_owned()))?;
    if ticks == 0 {
        return Err(CliError::InvalidWatchTicks(value.to_owned()));
    }
    Ok(ticks)
}

fn parse_watch_interval_ms(value: &str) -> CliResult<u64> {
    value
        .parse::<u64>()
        .map_err(|_| CliError::InvalidWatchInterval(value.to_owned()))
}

fn parse_tui_dimension(flag: &'static str, value: &str) -> CliResult<u16> {
    let dimension = value
        .parse::<u16>()
        .map_err(|_| CliError::InvalidTuiDimension {
            flag,
            value: value.to_owned(),
        })?;
    if dimension < 20 {
        return Err(CliError::InvalidTuiDimension {
            flag,
            value: value.to_owned(),
        });
    }
    Ok(dimension)
}

fn parse_tui_keys(value: &str) -> CliResult<Vec<TuiKey>> {
    value
        .split(',')
        .filter(|token| !token.trim().is_empty())
        .map(parse_tui_key)
        .collect()
}

fn parse_tui_key(value: &str) -> CliResult<TuiKey> {
    let trimmed = value.trim();
    match normalize_token(trimmed).as_str() {
        "tab" => Ok(TuiKey::Tab),
        "o" | "overview" => Ok(TuiKey::Focus(TuiPane::Overview)),
        "g" | "graph" | "graphs" | "graph-summary" => Ok(TuiKey::Focus(TuiPane::Graph)),
        "t" | "tasks" => Ok(TuiKey::Focus(TuiPane::Tasks)),
        "a" | "approvals" | "blockers" => Ok(TuiKey::Focus(TuiPane::Approvals)),
        "b" | "boundary" => Ok(TuiKey::Focus(TuiPane::Boundary)),
        "?" | "help" | "keys" => Ok(TuiKey::Focus(TuiPane::Keys)),
        "j" | "down" => Ok(TuiKey::MoveTaskDown),
        "k" | "up" => Ok(TuiKey::MoveTaskUp),
        "r" | "refresh" => Ok(TuiKey::Refresh),
        "q" | "quit" => Ok(TuiKey::Quit),
        _ if trimmed.starts_with('/') => Ok(TuiKey::Filter(trimmed[1..].to_owned())),
        _ => Err(CliError::InvalidTuiKey(trimmed.to_owned())),
    }
}

fn parse_tui_poll_ms(value: &str) -> CliResult<u64> {
    let millis = value
        .parse::<u64>()
        .map_err(|_| CliError::InvalidTuiPoll(value.to_owned()))?;
    if millis == 0 {
        return Err(CliError::InvalidTuiPoll(value.to_owned()));
    }
    Ok(millis)
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn boundary_report(surface: ShellSurface) -> BoundaryReport {
    BoundaryReport {
        surface,
        adapter_manifest: adapter_manifest(surface),
        supported_commands: vec![
            "admit", "manifest", "status", "watch", "tui", "boundary", "help", "repl",
        ],
        forbidden_commands: vec![
            "execute",
            "approve",
            "issue-ticket",
            "ticket",
            "verify",
            "commit",
            "ledger",
        ],
        trust_boundaries: vec![
            "submit_only",
            "projection_only",
            "approval_display_only",
        ],
        cannot_execute_directly: true,
        cannot_authorize: true,
        cannot_issue_tickets: true,
        cannot_verify: true,
        cannot_commit_ledger: true,
        note: "shell commands submit requests and render projections only; trusted P0 owns authorization, tickets, execution, verification, and ledger commits",
    }
}

fn write_json<T: serde::Serialize>(
    writer: &mut impl Write,
    value: &T,
    format: OutputFormat,
) -> CliResult<()> {
    if format.is_pretty() {
        writeln!(writer, "{}", serde_json::to_string_pretty(value)?)?;
    } else {
        writeln!(writer, "{}", serde_json::to_string(value)?)?;
    }
    Ok(())
}

fn write_boundary_text(writer: &mut impl Write, report: &BoundaryReport) -> CliResult<()> {
    writeln!(writer, "MOXI shell boundary")?;
    writeln!(writer, "surface: {:?}", report.surface)?;
    writeln!(writer, "shell: {}", report.adapter_manifest.shell_id)?;
    writeln!(
        writer,
        "permission_modes: {}",
        report
            .adapter_manifest
            .supported_permission_modes
            .iter()
            .map(|mode| format!("{mode:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(
        writer,
        "trust_boundaries: {}",
        report.trust_boundaries.join(", ")
    )?;
    writeln!(
        writer,
        "supported_commands: {}",
        report.supported_commands.join(", ")
    )?;
    writeln!(
        writer,
        "forbidden_commands: {}",
        report.forbidden_commands.join(", ")
    )?;
    writeln!(writer, "cannot_execute_directly: true")?;
    writeln!(writer, "cannot_authorize: true")?;
    writeln!(writer, "cannot_issue_tickets: true")?;
    writeln!(writer, "cannot_verify: true")?;
    writeln!(writer, "cannot_commit_ledger: true")?;
    writeln!(writer, "note: {}", report.note)?;
    Ok(())
}

fn write_status_text(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    render_limit: Option<usize>,
) -> CliResult<()> {
    writeln!(writer, "MOXI status")?;
    writeln!(writer, "surface: {:?}", projection.surface)?;
    writeln!(writer, "profile: {}", projection.profile_id)?;
    writeln!(
        writer,
        "graph: {}",
        projection.graph_id.as_deref().unwrap_or("<none>")
    )?;
    if let Some(goal) = &projection.graph_goal {
        writeln!(writer, "goal: {goal}")?;
    }
    if let Some(path) = projection.runtime_path {
        writeln!(writer, "path: {path:?}")?;
    }
    writeln!(
        writer,
        "stage: {}",
        projection
            .latest_stage
            .map(|stage| format!("{stage:?}"))
            .unwrap_or_else(|| "<none>".to_owned())
    )?;
    writeln!(writer, "progress: {}", percent(projection.latest_progress))?;
    writeln!(
        writer,
        "task: {}",
        projection.current_task_id.as_deref().unwrap_or("<none>")
    )?;
    writeln!(
        writer,
        "message: {}",
        projection.latest_message.as_deref().unwrap_or("<none>")
    )?;
    writeln!(writer, "cursor: {}", projection.event_cursor)?;
    writeln!(writer, "complete: {}", projection.is_complete)?;

    if projection.blockers.is_empty() {
        writeln!(writer, "blockers: none")?;
    } else {
        writeln!(writer, "blockers:")?;
        let shown = shown_count(render_limit, projection.blockers.len());
        for blocker in projection.blockers.iter().take(shown) {
            writeln!(writer, "- {}: {:?}", blocker.task_ref, blocker.blocker)?;
        }
        write_hidden_text(writer, "blockers", projection.blockers.len(), shown)?;
    }

    if !projection.graphs.is_empty() {
        writeln!(writer, "graphs:")?;
        let shown = shown_count(render_limit, projection.graphs.len());
        for graph in projection.graphs.iter().take(shown) {
            writeln!(
                writer,
                "- {} path={:?} tasks={} completed={} running={} awaiting={} blocked={} failed={} complete={}",
                graph.graph_id,
                graph.path,
                graph.task_count,
                graph.completed_count,
                graph.running_count,
                graph.awaiting_approval_count,
                graph.blocked_count,
                graph.failed_count,
                graph.is_complete
            )?;
        }
        write_hidden_text(writer, "graphs", projection.graphs.len(), shown)?;
    }

    if !projection.tasks.is_empty() {
        writeln!(writer, "tasks:")?;
        let shown = shown_count(render_limit, projection.tasks.len());
        for task in projection.tasks.iter().take(shown) {
            writeln!(
                writer,
                "- {} state={} capability={} progress={} blocker={} message={}",
                task.task_id,
                task.state,
                task.capability_id,
                percent(task.progress),
                task.blocker
                    .as_ref()
                    .map(|blocker| format!("{blocker:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                task.message.as_deref().unwrap_or("<none>")
            )?;
        }
        write_hidden_text(writer, "tasks", projection.tasks.len(), shown)?;
    }

    Ok(())
}

fn write_status_panel(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    render_limit: Option<usize>,
) -> CliResult<()> {
    let width = 72;
    write_panel_rule(writer, width)?;
    write_panel_row(writer, width, "MOXI CLI STATUS")?;
    write_panel_rule(writer, width)?;
    write_panel_row(
        writer,
        width,
        &format!(
            "surface={:?} profile={}",
            projection.surface, projection.profile_id
        ),
    )?;
    write_panel_row(
        writer,
        width,
        &format!(
            "graph={} cursor={} complete={}",
            projection.graph_id.as_deref().unwrap_or("<none>"),
            projection.event_cursor,
            projection.is_complete
        ),
    )?;
    if let Some(goal) = &projection.graph_goal {
        write_panel_row(writer, width, &format!("goal={goal}"))?;
    }
    if let Some(path) = projection.runtime_path {
        write_panel_row(writer, width, &format!("path={path:?}"))?;
    }
    write_panel_rule(writer, width)?;
    write_panel_row(
        writer,
        width,
        &format!(
            "stage={} progress={} task={}",
            projection
                .latest_stage
                .map(|stage| format!("{stage:?}"))
                .unwrap_or_else(|| "<none>".to_owned()),
            percent(projection.latest_progress),
            projection.current_task_id.as_deref().unwrap_or("<none>")
        ),
    )?;
    write_panel_row(
        writer,
        width,
        &format!(
            "message={}",
            projection.latest_message.as_deref().unwrap_or("<none>")
        ),
    )?;
    write_panel_rule(writer, width)?;

    if projection.blockers.is_empty() {
        write_panel_row(writer, width, "blockers: none")?;
    } else {
        write_panel_row(writer, width, "blockers:")?;
        let shown = shown_count(render_limit, projection.blockers.len());
        for blocker in projection.blockers.iter().take(shown) {
            write_panel_row(
                writer,
                width,
                &format!("  {} -> {:?}", blocker.task_ref, blocker.blocker),
            )?;
        }
        write_hidden_panel_row(writer, width, "blockers", projection.blockers.len(), shown)?;
    }

    if !projection.graphs.is_empty() {
        write_panel_rule(writer, width)?;
        write_panel_row(writer, width, "graphs:")?;
        let shown = shown_count(render_limit, projection.graphs.len());
        for graph in projection.graphs.iter().take(shown) {
            write_panel_row(
                writer,
                width,
                &format!(
                    "  {} tasks={} done={} run={} wait={} block={} fail={}",
                    graph.graph_id,
                    graph.task_count,
                    graph.completed_count,
                    graph.running_count,
                    graph.awaiting_approval_count,
                    graph.blocked_count,
                    graph.failed_count
                ),
            )?;
        }
        write_hidden_panel_row(writer, width, "graphs", projection.graphs.len(), shown)?;
    }

    if !projection.tasks.is_empty() {
        write_panel_rule(writer, width)?;
        write_panel_row(writer, width, "tasks:")?;
        let shown = shown_count(render_limit, projection.tasks.len());
        for task in projection.tasks.iter().take(shown) {
            write_panel_row(
                writer,
                width,
                &format!(
                    "  {} [{}] {} {}",
                    task.task_id,
                    task.state,
                    task.capability_id,
                    percent(task.progress)
                ),
            )?;
            if let Some(blocker) = &task.blocker {
                write_panel_row(writer, width, &format!("    blocker={blocker:?}"))?;
            }
            if let Some(message) = &task.message {
                write_panel_row(writer, width, &format!("    message={message}"))?;
            }
        }
        write_hidden_panel_row(writer, width, "tasks", projection.tasks.len(), shown)?;
    }

    write_panel_rule(writer, width)?;
    write_panel_row(
        writer,
        width,
        "boundary: projection only; no execute/approve/ticket/verify/ledger",
    )?;
    write_panel_rule(writer, width)?;
    Ok(())
}

fn write_tui_snapshot(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
    width: u16,
    height: u16,
) -> CliResult<()> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend terminal creation cannot fail");
    terminal
        .draw(|frame| {
            let area = frame.area();
            render_tui_snapshot(frame, area, projection, state);
        })
        .expect("test backend draw cannot fail");
    let buffer = terminal.backend().buffer();
    for y in 0..buffer.area.height {
        let mut line = String::new();
        for x in 0..buffer.area.width {
            line.push_str(buffer.cell((x, y)).map(|cell| cell.symbol()).unwrap_or(" "));
        }
        writeln!(writer, "{}", line.trim_end())?;
    }
    Ok(())
}

fn render_tui_snapshot(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(3),
        ])
        .split(area);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(vertical[1]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(28),
            Constraint::Percentage(38),
        ])
        .split(body[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(32),
            Constraint::Percentage(18),
        ])
        .split(body[1]);

    frame.render_widget(tui_header(projection, state), vertical[0]);
    frame.render_widget(tui_overview(projection, state), left[0]);
    frame.render_widget(tui_graph_summary(projection, state), left[1]);
    frame.render_widget(tui_blockers(projection, state), left[2]);
    frame.render_widget(tui_tasks(projection, state), right[0]);
    frame.render_widget(tui_task_detail(projection, state), right[1]);
    frame.render_widget(tui_boundary(state), right[2]);
    frame.render_widget(tui_footer(state), vertical[2]);
}

fn tui_header(projection: &moxi_shells::ShellProjection, state: &TuiState) -> Paragraph<'static> {
    Paragraph::new(Line::from(vec![
        Span::styled(
            "MOXI R10 TUI",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw(format!(
            "surface={:?} profile={} graph={} cursor={} pane={} refresh={}",
            projection.surface,
            projection.profile_id,
            projection.graph_id.as_deref().unwrap_or("<none>"),
            projection.event_cursor,
            state.active_pane.label(),
            state.refresh_count
        )),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Snapshot Shell"),
    )
}

fn tui_overview(projection: &moxi_shells::ShellProjection, state: &TuiState) -> Paragraph<'static> {
    let lines = vec![
        Line::from(format!(
            "filter: {}",
            state.filter.as_deref().unwrap_or("<none>")
        )),
        Line::from(format!(
            "goal: {}",
            projection.graph_goal.as_deref().unwrap_or("<none>")
        )),
        Line::from(format!(
            "stage: {}",
            projection
                .latest_stage
                .map(|stage| format!("{stage:?}"))
                .unwrap_or_else(|| "<none>".to_owned())
        )),
        Line::from(format!("progress: {}", percent(projection.latest_progress))),
        Line::from(format!(
            "task: {}",
            projection.current_task_id.as_deref().unwrap_or("<none>")
        )),
        Line::from(format!("complete: {}", projection.is_complete)),
        Line::from(format!(
            "message: {}",
            projection.latest_message.as_deref().unwrap_or("<none>")
        )),
    ];
    Paragraph::new(lines)
        .block(tui_block("Overview", TuiPane::Overview, state.active_pane))
        .wrap(Wrap { trim: true })
}

fn tui_graph_summary(
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) -> Paragraph<'static> {
    let lines = if projection.graphs.is_empty() {
        vec![Line::from("graph: <none>")]
    } else {
        projection
            .graphs
            .iter()
            .map(|graph| {
                Line::from(format!(
                    "{} t={} d={} r={} w={} b={} f={}",
                    graph.graph_id,
                    graph.task_count,
                    graph.completed_count,
                    graph.running_count,
                    graph.awaiting_approval_count,
                    graph.blocked_count,
                    graph.failed_count
                ))
            })
            .collect::<Vec<_>>()
    };
    Paragraph::new(lines)
        .block(tui_block(
            "Graph Summary",
            TuiPane::Graph,
            state.active_pane,
        ))
        .wrap(Wrap { trim: true })
}

fn tui_blockers(projection: &moxi_shells::ShellProjection, state: &TuiState) -> Paragraph<'static> {
    let mut lines = Vec::new();
    let awaiting_approval = projection
        .blockers
        .iter()
        .filter(|blocker| blocker.blocker == ResumeBlocker::AwaitingApproval)
        .count();
    lines.push(Line::from(format!(
        "approvals: awaiting={} display-only",
        awaiting_approval
    )));
    lines.push(Line::from("action: unavailable in shell"));

    lines.extend(
        projection
            .blockers
            .iter()
            .filter(|blocker| {
                matches_filter(
                    state.filter.as_deref(),
                    &[&blocker.task_ref, &format!("{:?}", blocker.blocker)],
                )
            })
            .map(|blocker| Line::from(format!("{} -> {:?}", blocker.task_ref, blocker.blocker))),
    );

    let lines = if lines.is_empty() {
        vec![Line::from("approval hints: none")]
    } else {
        lines
    };
    let lines = if projection.blockers.is_empty() {
        vec![
            Line::from("approvals: none"),
            Line::from("action: unavailable in shell"),
            Line::from("blockers: none"),
        ]
    } else if lines.len() == 2 {
        vec![
            lines[0].clone(),
            lines[1].clone(),
            Line::from("no blockers match filter"),
        ]
    } else {
        lines
    };
    Paragraph::new(lines)
        .block(tui_block(
            "Approvals / Blockers",
            TuiPane::Approvals,
            state.active_pane,
        ))
        .wrap(Wrap { trim: true })
}

fn tui_tasks(projection: &moxi_shells::ShellProjection, state: &TuiState) -> Paragraph<'static> {
    let lines = if projection.tasks.is_empty() {
        vec![Line::from("no task rows in this projection")]
    } else {
        let tasks = filtered_tasks(projection, state);
        let selected = selected_index(state.selected_task_index, tasks.len());
        tasks
            .iter()
            .enumerate()
            .map(|(index, task)| {
                let cursor = if Some(index) == selected { ">" } else { " " };
                Line::from(format!(
                    "{cursor} {} [{}] {} {} blocker={} msg={}",
                    task.task_id,
                    task.state,
                    task.capability_id,
                    percent(task.progress),
                    task.blocker
                        .as_ref()
                        .map(|blocker| format!("{blocker:?}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    task.message.as_deref().unwrap_or("<none>")
                ))
            })
            .collect::<Vec<_>>()
    };
    let lines = if lines.is_empty() {
        vec![Line::from("no tasks match filter")]
    } else {
        lines
    };
    Paragraph::new(lines)
        .block(tui_block("Tasks", TuiPane::Tasks, state.active_pane))
        .wrap(Wrap { trim: true })
}

fn tui_task_detail(
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) -> Paragraph<'static> {
    let lines = if let Some(task) = selected_task(projection, state) {
        vec![
            Line::from(format!("task: {}", task.task_id)),
            Line::from(format!(
                "state={} stage={} progress={}",
                task.state,
                task.last_stage
                    .map(|stage| format!("{stage:?}"))
                    .unwrap_or_else(|| "<none>".to_owned()),
                percent(task.progress)
            )),
            Line::from(format!(
                "capability={} skill={}",
                task.capability_id,
                task.skill_id.as_deref().unwrap_or("<none>")
            )),
            Line::from(format!(
                "blocker={}",
                task.blocker
                    .as_ref()
                    .map(|blocker| format!("{blocker:?}"))
                    .unwrap_or_else(|| "none".to_owned())
            )),
            Line::from(format!(
                "message: {}",
                task.message.as_deref().unwrap_or("<none>")
            )),
            Line::from("detail: projection-only; no execution authority"),
        ]
    } else if state.filter.is_some() {
        vec![Line::from("no selected task matches filter")]
    } else {
        vec![Line::from("no selected task")]
    };
    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Task Detail"))
        .wrap(Wrap { trim: true })
}

fn tui_boundary(state: &TuiState) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from("mode: read-only projection shell"),
        Line::from("allowed: admit, manifest, status, watch, tui, boundary, repl"),
        Line::from("forbidden: execute, approve, ticket, verify, commit, ledger"),
        Line::from("P0 owns authorization, tickets, execution, verification, ledger"),
    ])
    .block(tui_block("Boundary", TuiPane::Boundary, state.active_pane))
    .wrap(Wrap { trim: true })
}

fn tui_footer(state: &TuiState) -> Paragraph<'static> {
    Paragraph::new(format!(
        "active={} selected_task={} filter={} quit={} | Tab cycle | o/g/t/a/b/? focus | j/k task | /filter | r refresh snapshot | q exit | no execute/approve/ticket/verify/ledger",
        state.active_pane.label(),
        state.selected_task_index,
        state.filter.as_deref().unwrap_or("<none>"),
        state.should_quit
    ))
        .block(tui_block("Keys", TuiPane::Keys, state.active_pane))
        .wrap(Wrap { trim: true })
}

fn tui_block(title: &'static str, pane: TuiPane, active: TuiPane) -> Block<'static> {
    let title = if pane == active {
        format!("* {title}")
    } else {
        title.to_owned()
    };
    Block::default().borders(Borders::ALL).title(title)
}

fn selected_index(index: usize, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(index.min(len - 1))
    }
}

fn selected_task<'a>(
    projection: &'a moxi_shells::ShellProjection,
    state: &TuiState,
) -> Option<&'a moxi_shells::ShellTaskView> {
    let tasks = filtered_tasks(projection, state);
    selected_index(state.selected_task_index, tasks.len())
        .and_then(|index| tasks.get(index).copied())
}

fn filtered_tasks<'a>(
    projection: &'a moxi_shells::ShellProjection,
    state: &TuiState,
) -> Vec<&'a moxi_shells::ShellTaskView> {
    projection
        .tasks
        .iter()
        .filter(|task| {
            matches_filter(
                state.filter.as_deref(),
                &[
                    &task.task_id,
                    &task.state,
                    &task.capability_id,
                    task.message.as_deref().unwrap_or(""),
                ],
            )
        })
        .collect()
}

fn matches_filter(filter: Option<&str>, fields: &[&str]) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let filter = normalize_token(filter);
    fields
        .iter()
        .any(|field| normalize_token(field).contains(&filter))
}

fn shown_count(render_limit: Option<usize>, total: usize) -> usize {
    render_limit.unwrap_or(total).min(total)
}

fn write_hidden_text(
    writer: &mut impl Write,
    label: &str,
    total: usize,
    shown: usize,
) -> CliResult<()> {
    if total > shown {
        writeln!(
            writer,
            "- {} more {} hidden by --limit",
            total - shown,
            label
        )?;
    }
    Ok(())
}

fn write_hidden_panel_row(
    writer: &mut impl Write,
    width: usize,
    label: &str,
    total: usize,
    shown: usize,
) -> CliResult<()> {
    if total > shown {
        write_panel_row(
            writer,
            width,
            &format!("  ... {} more {} hidden by --limit", total - shown, label),
        )?;
    }
    Ok(())
}

fn write_panel_rule(writer: &mut impl Write, width: usize) -> CliResult<()> {
    writeln!(writer, "+{}+", "-".repeat(width.saturating_sub(2)))?;
    Ok(())
}

fn write_panel_row(writer: &mut impl Write, width: usize, text: &str) -> CliResult<()> {
    let inner_width = width.saturating_sub(4);
    let mut remaining = text;
    if remaining.is_empty() {
        writeln!(writer, "| {:inner_width$} |", "")?;
        return Ok(());
    }
    while !remaining.is_empty() {
        let split = split_at_char_boundary(remaining, inner_width);
        let (line, rest) = remaining.split_at(split);
        writeln!(writer, "| {:inner_width$} |", line)?;
        remaining = rest.trim_start();
    }
    Ok(())
}

fn split_at_char_boundary(text: &str, max_bytes: usize) -> usize {
    if text.len() <= max_bytes {
        return text.len();
    }
    let mut split = 0;
    for (index, _) in text.char_indices() {
        if index > max_bytes {
            break;
        }
        split = index;
    }
    split.max(1)
}

fn percent(value: f32) -> String {
    let value = if value.is_finite() { value } else { 0.0 };
    format!("{:.0}%", value.clamp(0.0, 1.0) * 100.0)
}

fn help_text() -> &'static str {
    "moxi-cli\n\nCommands:\n  admit --goal <text> [--tenant <id>] [--user <id>] [--workspace <path>] [--capability <id>] [--risk low|medium|high|critical]\n  manifest [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human]\n  boundary [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--text]\n  status [--feed|--query] [--input <snapshot.json>] [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--profile <id>] [--text|--panel] [--limit <n>]\n  watch [--feed|--query] --input <snapshot.json> [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--profile <id>] [--text|--panel] [--limit <n>] [--ticks <n>] [--interval-ms <n>]\n  tui [--feed|--query] --input <snapshot.json> [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--profile <id>] [--width <n>] [--height <n>] [--keys tab,o,g,t,a,b,?,j,k,/filter,r,q] [--interactive] [--poll-ms <n>]\n  repl\n\nBoundary: this CLI submits requests and renders shell contracts only; it can watch snapshot files and render a read-only TUI preview, but it cannot execute, authorize, issue tickets, verify, or commit ledger events."
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn event_feed_json() -> String {
        serde_json::json!({
            "schema_version": 1,
            "graph_id": "graph_1",
            "from_cursor": 0,
            "next_cursor": 2,
            "event_count": 1,
            "events": [],
            "latest_stage": "planned",
            "latest_message": "planning graph",
            "latest_progress": 0.25,
            "current_task_id": "task_1",
            "blockers": {},
            "is_complete": false,
            "generated_at": "2026-05-26T05:30:00Z"
        })
        .to_string()
    }

    fn query_snapshot_json() -> String {
        serde_json::json!({
            "graph": {
                "graph_id": "graph_detail",
                "goal": "read project",
                "path": "task_path",
                "task_count": 1,
                "completed_count": 0,
                "running_count": 0,
                "blocked_count": 1,
                "awaiting_approval_count": 1,
                "failed_count": 0,
                "is_complete": false
            },
            "planner": null,
            "tasks": [{
                "task_id": "task_1",
                "skill_id": "skill.file.read",
                "capability_id": "file.read",
                "target": {
                    "resource_type": "file",
                    "resource_ref": "README.md"
                },
                "state": "awaiting_approval",
                "last_stage": "awaiting_approval",
                "progress": 0.5,
                "message": "waiting for approval",
                "idempotency_key": null,
                "retry_safe": null,
                "blocker": "awaiting_approval",
                "updated_at": "2026-05-26T05:30:00Z"
            }],
            "attempts": [],
            "adoption_probes": [],
            "events": [{
                "event_id": "event_1",
                "graph_id": "graph_detail",
                "run_id": "run_1",
                "task_id": "task_1",
                "stage": "awaiting_approval",
                "message": "waiting for approval",
                "progress": 0.5,
                "timestamp": "2026-05-26T05:30:00Z"
            }],
            "resume_plan": {
                "graph_id": "graph_detail",
                "completed_task_ids": [],
                "ready_task_ids": [],
                "blocked_task_ids": ["task_1"],
                "running_task_ids": [],
                "awaiting_approval_task_ids": ["task_1"],
                "failed_task_ids": [],
                "blockers": {
                    "task_1": "awaiting_approval"
                },
                "adoption_recommendations": {},
                "running_task_policy": "require_inspection",
                "is_complete": false
            },
            "event_cursor": 3,
            "policy_profile": {
                "profile_id": "shell.ide.readonly",
                "allowed_capabilities": ["file.read"],
                "allow_fast_path": false,
                "allow_task_path": true,
                "allow_trusted_execution_path": false,
                "allow_skills": true,
                "allow_running_task_retry": false,
                "max_tasks_per_graph": 8
            }
        })
        .to_string()
    }

    fn multi_task_query_snapshot_json() -> String {
        let task = |id: &str, state: &str, stage: &str, blocker: Option<&str>, progress: f32| {
            serde_json::json!({
                "task_id": id,
                "skill_id": "skill.file.read",
                "capability_id": "file.read",
                "target": {
                    "resource_type": "file",
                    "resource_ref": format!("{id}.md")
                },
                "state": state,
                "last_stage": stage,
                "progress": progress,
                "message": format!("{id} message"),
                "idempotency_key": null,
                "retry_safe": null,
                "blocker": blocker,
                "updated_at": "2026-05-26T05:30:00Z"
            })
        };
        serde_json::json!({
            "graph": {
                "graph_id": "graph_many",
                "goal": "read many files",
                "path": "task_path",
                "task_count": 3,
                "completed_count": 0,
                "running_count": 1,
                "blocked_count": 2,
                "awaiting_approval_count": 1,
                "failed_count": 0,
                "is_complete": false
            },
            "planner": null,
            "tasks": [
                task("task_1", "awaiting_approval", "awaiting_approval", Some("awaiting_approval"), 0.1),
                task("task_2", "planned", "planned", Some("dependency_incomplete"), 0.2),
                task("task_3", "running", "executing", None, 0.3)
            ],
            "attempts": [],
            "adoption_probes": [],
            "events": [{
                "event_id": "event_1",
                "graph_id": "graph_many",
                "run_id": "run_1",
                "task_id": "task_1",
                "stage": "awaiting_approval",
                "message": "waiting",
                "progress": 0.1,
                "timestamp": "2026-05-26T05:30:00Z"
            }],
            "resume_plan": {
                "graph_id": "graph_many",
                "completed_task_ids": [],
                "ready_task_ids": [],
                "blocked_task_ids": ["task_2"],
                "running_task_ids": ["task_3"],
                "awaiting_approval_task_ids": ["task_1"],
                "failed_task_ids": [],
                "blockers": {
                    "task_1": "awaiting_approval",
                    "task_2": "dependency_incomplete"
                },
                "adoption_recommendations": {},
                "running_task_policy": "require_inspection",
                "is_complete": false
            },
            "event_cursor": 7,
            "policy_profile": {
                "profile_id": "shell.ide.readonly",
                "allowed_capabilities": ["file.read"],
                "allow_fast_path": false,
                "allow_task_path": true,
                "allow_trusted_execution_path": false,
                "allow_skills": true,
                "allow_running_task_retry": false,
                "max_tasks_per_graph": 8
            }
        })
        .to_string()
    }

    #[test]
    fn admit_outputs_submit_only_shell_admission_json() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "admit",
                "--tenant",
                "tenant_a",
                "--user",
                "user_a",
                "--workspace",
                "/workspace",
                "--goal",
                "read status",
                "--capability",
                "file.read",
            ],
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["surface"], "cli");
        assert_eq!(json["policy_profile"]["profile_id"], "shell.cli.fast");
        assert_eq!(json["normalized_entry"]["candidate"]["goal"], "read status");
        assert_eq!(
            json["normalized_entry"]["candidate"]["requested_capabilities"],
            serde_json::json!(["file.read"])
        );
        assert_eq!(json["cannot_execute_directly"], true);
        assert_eq!(json["cannot_authorize"], true);
    }

    #[test]
    fn high_risk_admit_marks_trusted_execution_path() {
        let mut output = Vec::new();

        run(
            [
                "moxi-cli",
                "admit",
                "--workspace",
                "/workspace",
                "--goal",
                "inspect risky change",
                "--risk",
                "high",
            ],
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(json["requires_trusted_execution_path"], true);
        assert_eq!(json["approval_hint"]["status"], "awaiting_approval");
    }

    #[test]
    fn manifest_outputs_read_only_cli_surface() {
        let mut output = Vec::new();

        run(["moxi-cli", "manifest", "--surface", "cli"], &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(json["shell_id"], "shell.cli");
        assert_eq!(json["surface"], "cli");
        assert_eq!(
            json["supported_permission_modes"],
            serde_json::json!(["read_only"])
        );
    }

    #[test]
    fn boundary_outputs_non_authorizing_shell_contract() {
        let mut output = Vec::new();

        run(["moxi-cli", "boundary", "--surface", "cli"], &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(json["surface"], "cli");
        assert_eq!(json["adapter_manifest"]["shell_id"], "shell.cli");
        assert_eq!(json["cannot_execute_directly"], true);
        assert_eq!(json["cannot_authorize"], true);
        assert_eq!(json["cannot_issue_tickets"], true);
        assert_eq!(json["cannot_verify"], true);
        assert_eq!(json["cannot_commit_ledger"], true);
        assert_eq!(
            json["forbidden_commands"],
            serde_json::json!([
                "execute",
                "approve",
                "issue-ticket",
                "ticket",
                "verify",
                "commit",
                "ledger"
            ])
        );
    }

    #[test]
    fn boundary_can_render_readable_text() {
        let mut output = Vec::new();

        run(["moxi-cli", "boundary", "--text"], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("MOXI shell boundary"));
        assert!(text.contains("surface: Cli"));
        assert!(text.contains("permission_modes: ReadOnly"));
        assert!(
            text.contains("trust_boundaries: submit_only, projection_only, approval_display_only")
        );
        assert!(text.contains("forbidden_commands: execute, approve"));
        assert!(text.contains("cannot_commit_ledger: true"));
    }

    #[test]
    fn rejects_missing_goal() {
        let mut output = Vec::new();

        let error = run(
            ["moxi-cli", "admit", "--workspace", "/workspace"],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::MissingRequired("--goal")));
        assert!(output.is_empty());
    }

    #[test]
    fn rejects_execute_as_unknown_command() {
        let mut output = Vec::new();

        let error = run(["moxi-cli", "execute"], &mut output).unwrap_err();

        assert!(matches!(error, CliError::UnknownCommand(command) if command == "execute"));
        assert!(output.is_empty());
    }

    #[test]
    fn status_projects_runtime_event_feed_from_stdin() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["surface"], "cli");
        assert_eq!(json["profile_id"], "shell.cli.fast");
        assert_eq!(json["graph_id"], "graph_1");
        assert_eq!(json["latest_stage"], "planned");
        assert_eq!(json["latest_message"], "planning graph");
        assert_eq!(json["current_task_id"], "task_1");
        assert_eq!(json["event_cursor"], 2);
    }

    #[test]
    fn status_tolerates_utf8_bom_from_piped_stdin() {
        let input = format!("\u{feff}{}", event_feed_json());
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["graph_id"], "graph_1");
        assert_eq!(json["latest_message"], "planning graph");
    }

    #[test]
    fn status_rejects_mismatched_graph_id() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let error = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_other"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap_err();

        assert!(
            matches!(error, CliError::GraphMismatch { expected, actual } if expected == "graph_other" && actual == "graph_1")
        );
        assert!(output.is_empty());
    }

    #[test]
    fn status_projects_runtime_query_snapshot_from_stdin() {
        let input = query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["surface"], "ide");
        assert_eq!(json["profile_id"], "shell.ide.readonly");
        assert_eq!(json["graph_id"], "graph_detail");
        assert_eq!(json["graph_goal"], "read project");
        assert_eq!(json["graphs"][0]["awaiting_approval_count"], 1);
        assert_eq!(json["tasks"][0]["task_id"], "task_1");
        assert_eq!(json["tasks"][0]["blocker"], "awaiting_approval");
        assert_eq!(json["event_cursor"], 3);
    }

    #[test]
    fn status_can_render_event_feed_as_readable_text() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1", "--text"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI status"));
        assert!(text.contains("surface: Cli"));
        assert!(text.contains("graph: graph_1"));
        assert!(text.contains("stage: Planned"));
        assert!(text.contains("progress: 25%"));
        assert!(text.contains("task: task_1"));
        assert!(text.contains("message: planning graph"));
        assert!(text.contains("blockers: none"));
    }

    #[test]
    fn status_can_render_query_snapshot_as_readable_text() {
        let input = query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--text",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("goal: read project"));
        assert!(text.contains("path: TaskPath"));
        assert!(text.contains("graphs:"));
        assert!(text.contains("awaiting=1"));
        assert!(text.contains("tasks:"));
        assert!(text.contains("state=AwaitingApproval"));
        assert!(text.contains("blocker=AwaitingApproval"));
    }

    #[test]
    fn status_can_render_event_feed_as_static_panel() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1", "--panel"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text
            .contains("+----------------------------------------------------------------------+"));
        assert!(text.contains("MOXI CLI STATUS"));
        assert!(text.contains("surface=Cli profile=shell.cli.fast"));
        assert!(text.contains("graph=graph_1 cursor=2 complete=false"));
        assert!(text.contains("stage=Planned progress=25% task=task_1"));
        assert!(text.contains("blockers: none"));
        assert!(text.contains("boundary: projection only; no execute/approve/ticket/verify/ledger"));
    }

    #[test]
    fn status_can_render_query_snapshot_as_static_panel() {
        let input = query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--panel",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("surface=Ide profile=shell.ide.readonly"));
        assert!(text.contains("goal=read project"));
        assert!(text.contains("path=TaskPath"));
        assert!(text.contains("graphs:"));
        assert!(text.contains("graph_detail tasks=1 done=0 run=0 wait=1 block=1 fail=0"));
        assert!(text.contains("tasks:"));
        assert!(text.contains("task_1 [AwaitingApproval] file.read 50%"));
        assert!(text.contains("blocker=AwaitingApproval"));
    }

    #[test]
    fn status_text_limit_hides_extra_rendered_rows_only() {
        let input = multi_task_query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--text",
                "--limit",
                "1",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("- task_1: AwaitingApproval"));
        assert!(text.contains("- 1 more blockers hidden by --limit"));
        assert!(text.contains("- task_1 state=AwaitingApproval"));
        assert!(text.contains("- 2 more tasks hidden by --limit"));
        assert!(!text.contains("task_3 state=Running"));
    }

    #[test]
    fn status_panel_limit_hides_extra_rendered_rows_only() {
        let input = multi_task_query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--panel",
                "--limit",
                "1",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("task_1 -> AwaitingApproval"));
        assert!(text.contains("... 1 more blockers hidden by --limit"));
        assert!(text.contains("task_1 [AwaitingApproval] file.read 10%"));
        assert!(text.contains("... 2 more tasks hidden by --limit"));
        assert!(!text.contains("task_3 [Running]"));
    }

    #[test]
    fn status_limit_does_not_truncate_json_projection() {
        let input = multi_task_query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--limit",
                "1",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["tasks"].as_array().unwrap().len(), 3);
        assert_eq!(json["blockers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn status_rejects_invalid_limit() {
        let mut output = Vec::new();

        let error = run_with_io(
            ["moxi-cli", "status", "--limit", "many"],
            event_feed_json().as_bytes(),
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidLimit(value) if value == "many"));
        assert!(output.is_empty());
    }

    #[test]
    fn status_rejects_conflicting_input_modes() {
        let mut output = Vec::new();

        let error = run_with_io(
            ["moxi-cli", "status", "--feed", "--query"],
            event_feed_json().as_bytes(),
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::StatusInputConflict));
        assert!(output.is_empty());
    }

    #[test]
    fn watch_renders_snapshot_file_as_panel_by_default() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "watch",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--ticks",
                "1",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("watch tick 1/1"));
        assert!(text.contains("MOXI CLI STATUS"));
        assert!(text.contains("surface=Ide profile=shell.ide.readonly"));
        assert!(text.contains("boundary: projection only; no execute/approve/ticket/verify/ledger"));
    }

    #[test]
    fn watch_can_render_multiple_text_ticks_without_runtime_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("event-feed.json");
        std::fs::write(&path, event_feed_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "watch",
                "--graph",
                "graph_1",
                "--input",
                path.to_str().unwrap(),
                "--text",
                "--ticks",
                "2",
                "--interval-ms",
                "0",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("watch tick 1/2"));
        assert!(text.contains("watch tick 2/2"));
        assert_eq!(text.matches("MOXI status").count(), 2);
        assert!(text.contains("stage: Planned"));
    }

    #[test]
    fn watch_requires_snapshot_input_path() {
        let mut output = Vec::new();

        let error = run(["moxi-cli", "watch", "--graph", "graph_1"], &mut output).unwrap_err();

        assert!(matches!(error, CliError::MissingRequired("--input")));
        assert!(output.is_empty());
    }

    #[test]
    fn watch_rejects_zero_ticks() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "watch",
                "--input",
                "snapshot.json",
                "--ticks",
                "0",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidWatchTicks(value) if value == "0"));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_renders_read_only_snapshot_dashboard() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "100",
                "--height",
                "28",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI R10 TUI"));
        assert!(text.contains("Overview"));
        assert!(text.contains("Graph Summary"));
        assert!(text.contains("Approvals / Blockers"));
        assert!(text.contains("Tasks"));
        assert!(text.contains("Boundary"));
        assert!(text.contains("graph=graph_detail"));
        assert!(text.contains("graph_detail t=1 d=0 r=0 w=1 b=1"));
        assert!(text.contains("f=0"));
        assert!(text.contains("approvals: awaiting=1"));
        assert!(text.contains("display-only"));
        assert!(text.contains("action: unavailable in shell"));
        assert!(text.contains("task_1 [AwaitingApproval] file.read 50%"));
        assert!(text.contains("mode: read-only projection shell"));
    }

    #[test]
    fn tui_requires_snapshot_input_path() {
        let mut output = Vec::new();

        let error = run(["moxi-cli", "tui", "--query"], &mut output).unwrap_err();

        assert!(matches!(error, CliError::MissingRequired("--input")));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_rejects_too_small_dimensions() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "tui",
                "--input",
                "snapshot.json",
                "--width",
                "10",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CliError::InvalidTuiDimension {
                flag: "--width",
                value
            } if value == "10"
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_keys_can_switch_panes_filter_refresh_and_quit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, multi_task_query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "112",
                "--height",
                "30",
                "--keys",
                "tab,tab,/task_2,r,q,tab",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Tasks"));
        assert!(text.contains("refresh=1"));
        assert!(text.contains("filter: task_2"));
        assert!(text.contains("active=Tasks selected_task=0 filter=task_2 quit=true"));
        assert!(text.contains("task_2 [Planned] file.read 20%"));
        assert!(text.contains("graph_many t=3 d=0 r=1 w=1 b=2 f=0"));
        assert!(text.contains("task: task_2"));
        assert!(text.contains("state=Planned stage=Planned progress=20%"));
        assert!(text.contains("blocker=DependencyIncomplete"));
        assert!(text.contains("detail: projection-only; no execution authority"));
        assert!(!text.contains("task_1 [AwaitingApproval]"));
        assert!(text.contains("task_2 -> DependencyIncomplete"));
    }

    #[test]
    fn tui_keys_can_focus_read_only_panes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "112",
                "--height",
                "30",
                "--keys",
                "graph,tasks,boundary,?,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Keys"));
        assert!(text.contains("active=Keys selected_task=0 filter=<none> quit=true"));
        assert!(text.contains("o/g/t/a/b/? focus"));
        assert!(text.contains("/filter"));
        assert!(text.contains("mode: read-only projection shell"));
    }

    #[test]
    fn tui_keys_can_focus_graph_summary_without_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "112",
                "--height",
                "30",
                "--keys",
                "g,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Graph"));
        assert!(text.contains("active=Graph selected_task=0 filter=<none> quit=true"));
        assert!(text.contains("* Graph Summary"));
        assert!(text.contains("graph_detail t=1 d=0 r=0 w=1 b=1 f=0"));
        assert!(text.contains("mode: read-only projection shell"));
    }

    #[test]
    fn tui_keys_can_move_task_selection_without_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, multi_task_query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "120",
                "--height",
                "30",
                "--keys",
                "j,j,k,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Tasks"));
        assert!(text.contains("active=Tasks selected_task=1"));
        assert!(text.contains("> task_2 [Planned] file.read 20%"));
        assert!(text.contains("task: task_2"));
        assert!(text.contains("state=Planned stage=Planned progress=20%"));
        assert!(text.contains("capability=file.read skill=skill.file.read"));
        assert!(text.contains("blocker=DependencyIncomplete"));
        assert!(text.contains("message: task_2 message"));
        assert!(text.contains("detail: projection-only; no execution authority"));
        assert!(text.contains("mode: read-only projection shell"));
    }

    #[test]
    fn tui_rejects_invalid_key_tokens() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "tui",
                "--input",
                "snapshot.json",
                "--keys",
                "execute",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidTuiKey(value) if value == "execute"));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_accepts_poll_option_in_snapshot_key_replay() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "100",
                "--height",
                "28",
                "--poll-ms",
                "10",
                "--keys",
                "q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("quit=true"));
        assert!(text.contains("MOXI R10 TUI"));
    }

    #[test]
    fn tui_rejects_zero_poll_interval() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "tui",
                "--input",
                "snapshot.json",
                "--poll-ms",
                "0",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidTuiPoll(value) if value == "0"));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_key_events_map_only_read_only_actions() {
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Tab)),
            Some(TuiKey::Tab)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Down)),
            Some(TuiKey::MoveTaskDown)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Up)),
            Some(TuiKey::MoveTaskUp)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('o'))),
            Some(TuiKey::Focus(TuiPane::Overview))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('G'))),
            Some(TuiKey::Focus(TuiPane::Graph))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('T'))),
            Some(TuiKey::Focus(TuiPane::Tasks))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('a'))),
            Some(TuiKey::Focus(TuiPane::Approvals))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('B'))),
            Some(TuiKey::Focus(TuiPane::Boundary))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('?'))),
            Some(TuiKey::Focus(TuiPane::Keys))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('j'))),
            Some(TuiKey::MoveTaskDown)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('K'))),
            Some(TuiKey::MoveTaskUp)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('r'))),
            Some(TuiKey::Refresh)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('q'))),
            Some(TuiKey::Quit)
        );
        assert_eq!(tui_key_from_event(KeyEvent::from(KeyCode::Enter)), None);
        assert_eq!(tui_key_from_event(KeyEvent::from(KeyCode::Char('x'))), None);
    }

    #[test]
    fn repl_admits_quoted_goal_and_exits() {
        let input = b"admit --workspace /workspace --goal \"read status\"\nexit\n";
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-cli repl"));
        assert!(text.contains("\"goal\":\"read status\""));
        assert!(text.contains("\"cannot_execute_directly\":true"));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_tolerates_utf8_bom_on_first_piped_line() {
        let input = b"\xEF\xBB\xBFadmit --workspace /workspace --goal \"read status\"\nexit\n";
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("\"goal\":\"read status\""));
        assert!(!text.contains("unknown command"));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_reports_unknown_command_without_stopping() {
        let input = b"execute\nmanifest --surface cli\nboundary --text\nquit\n";
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("error: unknown command: execute"));
        assert!(text.contains("\"shell_id\":\"shell.cli\""));
        assert!(text.contains("MOXI shell boundary"));
        assert!(text.contains("cannot_execute_directly: true"));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_rejects_unterminated_quotes() {
        let input = b"admit --goal \"read status\nquit\n";
        let mut output = Vec::new();

        run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("error: unterminated quoted string"));
    }

    #[test]
    fn repl_projects_status_without_exiting() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("event-feed.json");
        std::fs::write(&path, event_feed_json()).unwrap();
        let input = format!(
            "status --graph graph_1 --input \"{}\"\nexit\n",
            path.display()
        );
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], input.as_bytes(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("\"graph_id\":\"graph_1\""));
        assert!(text.contains("\"latest_message\":\"planning graph\""));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_projects_query_status_without_exiting() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let input = format!(
            "status --query --surface ide --graph graph_detail --input \"{}\"\nexit\n",
            path.display()
        );
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], input.as_bytes(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("\"graph_id\":\"graph_detail\""));
        assert!(text.contains("\"tasks\":["));
        assert!(text.contains("bye"));
    }
}
