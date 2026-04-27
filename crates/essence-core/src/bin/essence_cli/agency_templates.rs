use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AgencyAgentTemplate {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) category: String,
    pub(crate) description: String,
    pub(crate) lane: String,
    pub(crate) role: String,
    pub(crate) prompt: String,
    pub(crate) source_path: String,
}

pub(crate) fn bundled_agent_templates() -> Result<Vec<AgencyAgentTemplate>, serde_json::Error> {
    let raw = include_str!("../../../../../assets/agency-agents/templates.json")
        .trim_start_matches('\u{feff}')
        .trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(raw)
}

pub(crate) fn find_agent_template(
    query: &str,
) -> Result<Option<AgencyAgentTemplate>, serde_json::Error> {
    let normalized = normalize(query);
    Ok(bundled_agent_templates()?.into_iter().find(|template| {
        normalize(&template.id) == normalized || normalize(&template.name) == normalized
    }))
}

pub(crate) fn search_agent_templates(
    query: Option<&str>,
    category: Option<&str>,
) -> Result<Vec<AgencyAgentTemplate>, serde_json::Error> {
    let query = query.map(normalize);
    let category = category.map(normalize);
    let mut templates = bundled_agent_templates()?
        .into_iter()
        .filter(|template| {
            category
                .as_ref()
                .is_none_or(|category| normalize(&template.category) == *category)
        })
        .filter(|template| {
            query.as_ref().is_none_or(|query| {
                normalize(&template.id).contains(query)
                    || normalize(&template.name).contains(query)
                    || normalize(&template.description).contains(query)
                    || normalize(&template.category).contains(query)
            })
        })
        .collect::<Vec<_>>();
    templates.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(templates)
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '_'], "-")
}
