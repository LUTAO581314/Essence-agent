use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::support::CliError;

pub(crate) const DEFAULT_OPENAI_COMPATIBLE_BASE_URL: &str = "https://api.openai.com/v1";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct StoredModelConfig {
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
}

pub(crate) fn read_model_config(root: &Path) -> Result<Option<StoredModelConfig>, CliError> {
    let path = model_config_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub(crate) fn write_model_config(
    root: &Path,
    config: &StoredModelConfig,
) -> Result<PathBuf, CliError> {
    std::fs::create_dir_all(root)?;
    let path = model_config_path(root);
    let bytes = serde_json::to_vec_pretty(config)?;
    std::fs::write(&path, bytes)?;
    Ok(path)
}

pub(crate) fn model_config_path(root: &Path) -> PathBuf {
    root.join("model.json")
}

pub(crate) fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}
