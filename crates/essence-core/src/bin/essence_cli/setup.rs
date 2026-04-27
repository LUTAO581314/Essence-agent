use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::path::PathBuf;

use essence_core::ControlPlane;

use super::agency_templates::find_agent_template;
use super::agent_profile::{validate_agent_id, write_agent_profile, StoredAgentProfile};
use super::args::{CliModelProvider, SetupArgs};
use super::model_config::{
    non_empty, write_model_config, StoredModelConfig, DEFAULT_OPENAI_COMPATIBLE_BASE_URL,
};
use super::pixel_ui::{brand_header, key_value, mid, reset, row, status_chip, style, tiny_logo};
use super::support::{path_to_string, CliError};

pub(crate) fn execute_setup(
    control: &ControlPlane,
    args: SetupArgs,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let color = !args.no_color;
    let config = setup_config(&args);
    let agent_profile = setup_agent_profile(&args)?;
    let saved_model_path = if args.save {
        Some(write_model_config(control.root(), &config)?)
    } else {
        None
    };
    let saved_agent_path = if args.save {
        agent_profile
            .as_ref()
            .map(|profile| write_agent_profile(control.root(), profile))
            .transpose()?
    } else {
        None
    };
    let rendered = render_setup(
        &config,
        agent_profile.as_ref(),
        saved_model_path.as_ref(),
        saved_agent_path.as_ref(),
        color,
    );
    writer.write_all(rendered.as_bytes())?;
    Ok(())
}

fn setup_config(args: &SetupArgs) -> StoredModelConfig {
    let provider = provider_slug(args.model_provider).to_string();
    let base_url = match args.model_provider {
        CliModelProvider::OpenaiCompatible => non_empty(args.model_base_url.clone())
            .or_else(|| Some(DEFAULT_OPENAI_COMPATIBLE_BASE_URL.to_string())),
        CliModelProvider::Local | CliModelProvider::Command => {
            non_empty(args.model_base_url.clone())
        }
    };
    StoredModelConfig {
        provider: Some(provider),
        model: non_empty(args.model.clone()),
        base_url,
        api_key_env: non_empty(args.model_api_key_env.clone()),
        command: non_empty(args.model_command.clone()),
    }
}

fn setup_agent_profile(args: &SetupArgs) -> Result<Option<StoredAgentProfile>, CliError> {
    let should_create_agent = args.main_agent.is_some()
        || args.main_agent_lane.is_some()
        || args.main_agent_role.is_some()
        || args.main_agent_prompt.is_some()
        || args.main_agent_prompt_file.is_some()
        || args.main_agent_template.is_some();
    if !should_create_agent {
        return Ok(None);
    }

    let template = match args.main_agent_template.as_deref() {
        Some(template_id) => Some(
            find_agent_template(template_id)?
                .ok_or_else(|| CliError::MissingAgentTemplate(template_id.to_string()))?,
        ),
        None => None,
    };
    let mut profile = StoredAgentProfile::new(
        non_empty(args.main_agent.clone()).unwrap_or_else(|| "main".to_string()),
        non_empty(args.main_agent_role.clone())
            .or_else(|| template.as_ref().map(|template| template.role.clone()))
            .unwrap_or_else(|| "CLI Assistant".to_string()),
        non_empty(args.main_agent_lane.clone())
            .or_else(|| template.as_ref().map(|template| template.lane.clone()))
            .unwrap_or_else(|| "main".to_string()),
    );
    profile.system_prompt = non_empty(args.main_agent_prompt.clone())
        .or_else(|| template.as_ref().map(|template| template.prompt.clone()));
    profile.system_prompt_file = args
        .main_agent_prompt_file
        .as_ref()
        .map(|path| path_to_string(path))
        .transpose()?
        .and_then(|value| non_empty(Some(value)));
    profile.template_id = template.as_ref().map(|template| template.id.clone());
    validate_agent_id(&profile.agent_id)?;
    Ok(Some(profile))
}

fn render_setup(
    config: &StoredModelConfig,
    agent_profile: Option<&StoredAgentProfile>,
    saved_model_path: Option<&PathBuf>,
    saved_agent_path: Option<&PathBuf>,
    color: bool,
) -> String {
    let mut output = String::new();
    let ice = style(color, "ice");
    let moon = style(color, "moon");
    let dim = style(color, "dim");
    let reset = reset(color);
    let provider = config.provider.as_deref().unwrap_or("local");
    let model = config.model.as_deref().unwrap_or("your-model-name");
    let base_url = config
        .base_url
        .as_deref()
        .unwrap_or(DEFAULT_OPENAI_COMPATIBLE_BASE_URL);
    let api_key_env = config.api_key_env.as_deref().unwrap_or("OPENAI_API_KEY");
    let key_state = if std::env::var(api_key_env)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
    {
        status_chip(color, "KEY READY", "green")
    } else {
        status_chip(color, "KEY MISSING", "yellow")
    };

    output.push_str(&brand_header(
        "ESSENCE AGENT SETUP",
        "pixel terminal onboarding",
        color,
    ));
    let _ = writeln!(output, "{}", row(color, tiny_logo(color)));
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!("{ice}01 DOWNLOAD{reset}  get the local control plane")
        )
    );
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            "git clone https://github.com/LUTAO581314/Essence-agent"
        )
    );
    let _ = writeln!(output, "{}", row(color, "cd essence-agent"));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            "cargo install --path crates/essence-core --bin essence"
        )
    );
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(color, format!("{ice}02 CONFIGURE{reset} model defaults"))
    );
    let _ = writeln!(
        output,
        "{}",
        row(color, key_value(color, "provider", provider))
    );
    let _ = writeln!(output, "{}", row(color, key_value(color, "model", model)));
    let _ = writeln!(
        output,
        "{}",
        row(color, key_value(color, "base url", base_url))
    );
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!(
                "{} {}",
                key_value(color, "api key env", api_key_env),
                key_state
            )
        )
    );
    if let Some(profile) = agent_profile {
        let prompt_state =
            if profile.system_prompt.is_some() || profile.system_prompt_file.is_some() {
                status_chip(color, "PROMPT READY", "green")
            } else {
                status_chip(color, "NO PROMPT", "yellow")
            };
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!(
                    "{}   {}   {}",
                    key_value(color, "main agent", &profile.agent_id),
                    key_value(color, "lane", &profile.lane),
                    key_value(color, "role", &profile.role)
                )
            )
        );
        if let Some(template_id) = &profile.template_id {
            let _ = writeln!(
                output,
                "{}",
                row(color, key_value(color, "agent template", template_id))
            );
        }
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "agent prompt", &prompt_state))
        );
    }
    if let Some(path) = saved_model_path {
        let _ = writeln!(
            output,
            "{}",
            row(color, format!("{moon}saved{reset} {}", path.display()))
        );
    } else {
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!("{dim}preview only; add --save to write .essence config files{reset}")
            )
        );
    }
    if let Some(path) = saved_agent_path {
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!("{moon}saved agent{reset} {}", path.display())
            )
        );
    }
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(color, format!("{ice}03 CHAT{reset} start the shell"))
    );
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!(
                "essence chat{} --model-provider {provider} --model {model}",
                agent_profile
                    .map(|profile| format!(" --agent {}", profile.agent_id))
                    .unwrap_or_default()
            )
        )
    );
    let _ = writeln!(output, "{}", row(color, "inside chat: /office /help /exit"));
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(color, format!("{ice}04 BOARD{reset} watch agent presence"))
    );
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            "essence workspace dashboard --session-id <session-id>"
        )
    );
    let _ = writeln!(
        output,
        "{}",
        row(color, "essence workspace watch --session-id <session-id>")
    );
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!("{dim}tip:{reset} set {api_key_env}; config stores the env name, not the key")
        )
    );
    output
}

pub(crate) fn provider_slug(provider: CliModelProvider) -> &'static str {
    match provider {
        CliModelProvider::Local => "local",
        CliModelProvider::Command => "command",
        CliModelProvider::OpenaiCompatible => "openai-compatible",
    }
}
