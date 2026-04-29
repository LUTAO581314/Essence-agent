use moxi_contracts::{Budget, Intent, PermissionMode, RiskLevel};
use moxi_gateway::TrustedEntry;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntentCompilerError {
    #[error("gateway did not allow request: {0}")]
    GatewayDenied(String),
    #[error("compiled intent goal cannot be empty")]
    EmptyGoal,
    #[error("compiled capability cannot be empty")]
    EmptyCapability,
}

pub type IntentCompilerResult<T> = Result<T, IntentCompilerError>;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CompiledIntent {
    pub request_id: String,
    pub gateway_decision_ref: String,
    pub permission_mode: PermissionMode,
    pub intent: Intent,
}

pub struct IntentCompiler;

impl IntentCompiler {
    pub fn compile(entry: TrustedEntry) -> IntentCompilerResult<CompiledIntent> {
        if !entry.gateway_decision.allowed {
            return Err(IntentCompilerError::GatewayDenied(
                entry.gateway_decision.gateway_decision_id,
            ));
        }

        let goal = normalized_goal(&entry.candidate.goal)?;
        let requested_capabilities =
            compile_capabilities(entry.candidate.requested_capabilities, &goal)?;
        let risk_level = std::cmp::max(
            entry.candidate.risk_level,
            inferred_goal_risk(&goal, &requested_capabilities),
        );

        let gateway_decision_ref = entry.gateway_decision.gateway_decision_id;

        Ok(CompiledIntent {
            request_id: entry.request_id,
            gateway_decision_ref: gateway_decision_ref.clone(),
            permission_mode: entry.permission_mode,
            intent: Intent {
                intent_id: format!("intent_{}", Uuid::new_v4()),
                tenant_id: entry.candidate.tenant_id,
                user_id: entry.candidate.user_id,
                gateway_decision_ref: Some(gateway_decision_ref),
                goal,
                requested_capabilities,
                risk_level,
                workspace_root: entry.candidate.workspace_root,
                budget: normalized_budget(entry.candidate.budget),
            },
        })
    }
}

pub fn compile_intent(entry: TrustedEntry) -> IntentCompilerResult<CompiledIntent> {
    IntentCompiler::compile(entry)
}

fn normalized_goal(goal: &str) -> IntentCompilerResult<String> {
    let goal = goal.trim();
    if goal.is_empty() {
        return Err(IntentCompilerError::EmptyGoal);
    }
    Ok(goal.to_owned())
}

fn compile_capabilities(
    mut requested: Vec<String>,
    goal: &str,
) -> IntentCompilerResult<Vec<String>> {
    if requested.is_empty() && looks_like_file_read(goal) {
        requested.push("file.read".into());
    }

    let mut compiled = Vec::new();
    for capability in requested {
        let capability = capability.trim();
        if capability.is_empty() {
            return Err(IntentCompilerError::EmptyCapability);
        }
        if !compiled.iter().any(|existing| existing == capability) {
            compiled.push(capability.to_owned());
        }
    }
    Ok(compiled)
}

fn inferred_goal_risk(goal: &str, capabilities: &[String]) -> RiskLevel {
    let lowered = goal.to_ascii_lowercase();
    if lowered.contains("delete")
        || lowered.contains("overwrite")
        || lowered.contains("execute")
        || capabilities
            .iter()
            .any(|capability| capability.contains("write") || capability.contains("shell"))
    {
        RiskLevel::High
    } else if lowered.contains("network")
        || lowered.contains("http")
        || capabilities
            .iter()
            .any(|capability| capability.contains("network"))
    {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn looks_like_file_read(goal: &str) -> bool {
    let lowered = goal.to_ascii_lowercase();
    lowered.contains("read")
        || lowered.contains("open")
        || lowered.contains("show")
        || lowered.contains("inspect")
}

fn normalized_budget(budget: Budget) -> Budget {
    Budget {
        max_steps: budget.max_steps.max(1),
        max_heartbeats: budget.max_heartbeats.max(1),
        max_tool_calls: budget.max_tool_calls.max(1),
        max_cost_cents: budget.max_cost_cents,
        timeout_ms: budget.timeout_ms.max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moxi_contracts::{DeltaState, DeltaTarget, ResourceType, SandboxInput, WorldDelta};
    use moxi_core::{file_read_capability, ledger_event_for_success, Kernel};
    use moxi_entry::{normalize_entry, EntryChannel, EntryRequest};
    use moxi_gateway::admit_entry;
    use serde_json::json;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn compiles_trusted_entry_into_kernel_intent() {
        let request = EntryRequest::new(
            EntryChannel::Desktop,
            "tenant_a",
            "user_a",
            "/workspace",
            "read README.md",
        );
        let trusted = admit_entry(normalize_entry(request).unwrap()).unwrap();

        let compiled = compile_intent(trusted).unwrap();

        assert_eq!(compiled.permission_mode, PermissionMode::ReadOnly);
        assert_eq!(compiled.intent.requested_capabilities, vec!["file.read"]);
        assert_eq!(compiled.intent.risk_level, RiskLevel::Low);
    }

    #[test]
    fn full_trusted_ingress_understanding_execution_loop_reads_file() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(workspace.path().join("hello.txt"), "hello moxi").unwrap();

        let mut request = EntryRequest::new(
            EntryChannel::McpServer,
            "tenant_a",
            "user_a",
            workspace.path().to_string_lossy(),
            "read hello.txt",
        );
        request.requested_capabilities = vec!["file.read".into()];

        let trusted = admit_entry(normalize_entry(request).unwrap()).unwrap();
        let compiled = compile_intent(trusted).unwrap();

        let mut kernel = Kernel::new_in_memory(workspace.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit_with_permission_mode(compiled.intent, compiled.permission_mode)
            .unwrap();

        let delta = WorldDelta {
            delta_id: format!("delta_{}", Uuid::new_v4()),
            run_id: run.run_id.clone(),
            proposed_by: "intent_compiler".into(),
            capability_id: "file.read".into(),
            state: DeltaState::Draft,
            target: DeltaTarget {
                resource_type: ResourceType::File,
                resource_ref: "hello.txt".into(),
            },
            change_summary: "Read hello.txt".into(),
            preconditions: Vec::new(),
            patch_ref: None,
            evidence_refs: Vec::new(),
            risk_level: RiskLevel::Low,
            rollback_plan_ref: None,
        };
        let policy = kernel.propose_delta(&run.run_id, delta.clone()).unwrap();
        let capability = kernel.capability("file.read").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        let result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "hello.txt" }),
                },
            )
            .unwrap();
        let proof = kernel.verify(&result).unwrap();
        let event = ledger_event_for_success(
            &result,
            &proof,
            "hello.txt",
            &policy.decision_id,
            &delta.delta_id,
        );
        let committed = kernel.commit(event).unwrap();

        assert_eq!(result.output["content"], "hello moxi");
        assert_eq!(committed.result, moxi_contracts::EventResult::Success);
    }
}
