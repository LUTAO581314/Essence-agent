use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::model_config::non_empty;
use super::support::CliError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct StoredAgentProfile {
    pub(crate) agent_id: String,
    pub(crate) role: String,
    pub(crate) lane: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) system_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) system_prompt_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) api_key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) template_id: Option<String>,
}

impl StoredAgentProfile {
    pub(crate) fn new(
        agent_id: impl Into<String>,
        role: impl Into<String>,
        lane: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            role: role.into(),
            lane: lane.into(),
            system_prompt: None,
            system_prompt_file: None,
            provider: None,
            model: None,
            base_url: None,
            api_key_env: None,
            command: None,
            template_id: None,
        }
    }

    pub(crate) fn system_prompt_text(&self) -> Result<Option<String>, CliError> {
        if let Some(prompt) = non_empty(self.system_prompt.clone()) {
            return Ok(Some(prompt));
        }
        if let Some(path) = non_empty(self.system_prompt_file.clone()) {
            return read_prompt_file(&PathBuf::from(path)).map(Some);
        }
        Ok(None)
    }
}

pub(crate) fn read_agent_profile(
    root: &Path,
    agent_id: &str,
) -> Result<StoredAgentProfile, CliError> {
    validate_agent_id(agent_id)?;
    let path = agent_profile_path(root, agent_id);
    if !path.exists() {
        return Err(CliError::MissingAgentProfile(agent_id.to_string()));
    }
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn read_agent_profile_if_exists(
    root: &Path,
    agent_id: &str,
) -> Result<Option<StoredAgentProfile>, CliError> {
    validate_agent_id(agent_id)?;
    let path = agent_profile_path(root, agent_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub(crate) fn write_agent_profile(
    root: &Path,
    profile: &StoredAgentProfile,
) -> Result<PathBuf, CliError> {
    validate_agent_id(&profile.agent_id)?;
    let path = agent_profile_path(root, &profile.agent_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(profile)?;
    std::fs::write(&path, bytes)?;
    Ok(path)
}

pub(crate) fn list_agent_profiles(root: &Path) -> Result<Vec<StoredAgentProfile>, CliError> {
    let dir = agent_profiles_dir(root);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut profiles: Vec<StoredAgentProfile> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        profiles.push(serde_json::from_slice(&bytes)?);
    }
    profiles.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    Ok(profiles)
}

pub(crate) fn read_prompt_file(path: &Path) -> Result<String, CliError> {
    std::fs::read_to_string(path).map_err(CliError::from)
}

fn agent_profiles_dir(root: &Path) -> PathBuf {
    root.join("agents")
}

fn agent_profile_path(root: &Path, agent_id: &str) -> PathBuf {
    agent_profiles_dir(root).join(format!("{agent_id}.json"))
}

pub(crate) fn validate_agent_id(agent_id: &str) -> Result<(), CliError> {
    let is_valid = !agent_id.trim().is_empty()
        && agent_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
    if is_valid {
        Ok(())
    } else {
        Err(CliError::InvalidAgentId(agent_id.to_string()))
    }
}
