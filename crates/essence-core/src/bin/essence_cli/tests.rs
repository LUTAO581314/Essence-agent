use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use serde_json::Value;
use uuid::Uuid;

use super::args::*;
use super::chat::execute_chat;
use super::execute;
use super::workspace_view::execute_workspace;
use essence_core::{
    AgentHeartbeatRequest, ApprovalDecision, ContentBlock, ControlPlane, CreateSessionRequest,
    CreateTaskRequest, LifecycleStatus, MessagePayload, MessageRole, RegisterAgentRequest,
    RequestApprovalRequest,
};

#[test]
fn creates_session_via_cli() {
    let root = temp_root("create-session");
    let cwd = root.join("workspace");
    fs::create_dir_all(&cwd).unwrap();

    let cli = Cli {
        root: root.clone(),
        command: Command::Session(SessionArgs {
            command: SessionCommand::Create(SessionCreateArgs {
                cwd: Some(cwd.clone()),
                title: Some("First session".to_string()),
                model: Some("gpt-test".to_string()),
                mode: CliSessionMode::Interactive,
                permission_mode: CliPermissionMode::Default,
            }),
        }),
    };

    let mut out = Vec::new();
    execute(cli, &mut out).unwrap();

    let session: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(session["title"], "First session");
    assert_eq!(session["model"], "gpt-test");

    let session_id = session["session_id"].as_str().unwrap();
    let wal_path = root.join("sessions").join(format!("{session_id}.jsonl"));
    assert!(wal_path.exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn sends_message_via_cli() {
    let root = temp_root("send-message");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();

    let cli = Cli {
        root: root.clone(),
        command: Command::Message(MessageArgs {
            command: MessageCommand::Send(MessageSendArgs {
                session_id: session.session_id.0.to_string(),
                text: "hello from cli".to_string(),
            }),
        }),
    };

    let mut out = Vec::new();
    execute(cli, &mut out).unwrap();

    let event: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(event["event_type"], "message_user");

    let projection = control.projection(&session.session_id).unwrap();
    let payload: &MessagePayload = &projection.messages[0];
    assert_eq!(payload.role, MessageRole::User);
    assert_eq!(payload.content.len(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn tails_events_after_cursor() {
    let root = temp_root("tail-events");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    control
        .submit_user_message(&session.session_id, "first")
        .unwrap();
    control
        .submit_user_message(&session.session_id, "second")
        .unwrap();

    let cli = Cli {
        root: root.clone(),
        command: Command::Events(EventsArgs {
            command: EventsCommand::Tail(EventsTailArgs {
                session_id: session.session_id.0.to_string(),
                after: 2,
                user_visible: false,
                follow: false,
                interval_ms: 1,
            }),
        }),
    };

    let mut out = Vec::new();
    execute(cli, &mut out).unwrap();

    let lines = String::from_utf8(out).unwrap();
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "message_user");
    assert_eq!(events[0]["seq"], 3);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn verifies_event_integrity_via_cli() {
    let root = temp_root("verify-events");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    control
        .submit_user_message(&session.session_id, "verify me")
        .unwrap();

    let cli = Cli {
        root: root.clone(),
        command: Command::Events(EventsArgs {
            command: EventsCommand::Verify(EventsVerifyArgs {
                session_id: session.session_id.0.to_string(),
            }),
        }),
    };

    let mut out = Vec::new();
    execute(cli, &mut out).unwrap();

    let report: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["event_count"], 2);
    assert_eq!(report["latest_seq"], 2);
    assert!(report["latest_hash"].as_str().unwrap().len() >= 64);
    assert_eq!(report["findings"].as_array().unwrap().len(), 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn writes_and_verifies_event_anchor_via_cli() {
    let root = temp_root("anchor-events");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    control
        .submit_user_message(&session.session_id, "anchor me")
        .unwrap();
    let key_env = format!("ESSENCE_ANCHOR_KEY_{}", Uuid::new_v4().simple());
    std::env::set_var(&key_env, "test-anchor-secret");

    let write_cli = Cli {
        root: root.clone(),
        command: Command::Events(EventsArgs {
            command: EventsCommand::AnchorWrite(EventsAnchorWriteArgs {
                session_id: session.session_id.0.to_string(),
                key_id: "test-key".to_string(),
                key_env: key_env.clone(),
            }),
        }),
    };
    let mut out = Vec::new();
    execute(write_cli, &mut out).unwrap();
    let anchor: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(anchor["algorithm"], "hmac_sha256");
    assert_eq!(anchor["key_id"], "test-key");
    assert!(anchor["signature"].as_str().unwrap().len() >= 64);

    let verify_cli = Cli {
        root: root.clone(),
        command: Command::Events(EventsArgs {
            command: EventsCommand::AnchorVerify(EventsAnchorVerifyArgs {
                session_id: session.session_id.0.to_string(),
                key_env: key_env.clone(),
            }),
        }),
    };
    let mut out = Vec::new();
    execute(verify_cli, &mut out).unwrap();
    let verification: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(verification["integrity_valid"], true);
    assert_eq!(verification["latest_hash_matches"], true);
    assert_eq!(verification["signature_valid"], true);

    std::env::remove_var(key_env);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn lists_pending_approvals_via_cli() {
    let root = temp_root("pending-approvals");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    let approval = control
        .request_approval(RequestApprovalRequest::new(
            session.session_id.clone(),
            "shell",
            serde_json::json!({"command": "cargo test"}),
            "shell requires approval",
        ))
        .unwrap();

    let cli = Cli {
        root: root.clone(),
        command: Command::Approval(ApprovalArgs {
            command: ApprovalCommand::Pending(ApprovalPendingArgs {
                session_id: session.session_id.0.to_string(),
            }),
        }),
    };

    let mut out = Vec::new();
    execute(cli, &mut out).unwrap();

    let approvals: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(approvals.as_array().unwrap().len(), 1);
    assert_eq!(
        approvals[0]["approval_id"],
        approval.approval_id.0.to_string()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn resolves_approval_via_cli() {
    let root = temp_root("resolve-approval");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    let approval = control
        .request_approval(RequestApprovalRequest::new(
            session.session_id.clone(),
            "shell",
            serde_json::json!({"command": "cargo test"}),
            "shell requires approval",
        ))
        .unwrap();

    let cli = Cli {
        root: root.clone(),
        command: Command::Approval(ApprovalArgs {
            command: ApprovalCommand::Resolve(ApprovalResolveArgs {
                session_id: session.session_id.0.to_string(),
                approval_id: approval.approval_id.0.to_string(),
                decision: CliApprovalDecision::Deny,
                resolved_by: "tester".to_string(),
            }),
        }),
    };

    let mut out = Vec::new();
    execute(cli, &mut out).unwrap();

    let resolved: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(resolved["decision"], "deny");
    let projection = control.projection(&session.session_id).unwrap();
    let projected = projection.approvals.get(&approval.approval_id).unwrap();
    assert_eq!(projected.decision, Some(ApprovalDecision::Deny));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn chat_records_turns_and_renders_office_board() {
    let root = temp_root("chat");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();

    let args = ChatArgs {
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_command: None,
        model_timeout_ms: 30_000,
        model_max_stdout_bytes: 1_048_576,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("hello office\n/office\n/exit\n");
    let mut out = Vec::new();
    execute_chat(&control, args, &mut input, &mut out).unwrap();

    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("Essence chat session"));
    assert!(rendered.contains("assistant> local assistant: recorded `hello office`"));
    assert!(rendered.contains("ESSENCE AGENT // STAR OFFICE"));
    assert!(rendered.contains("main"));
    assert!(rendered.contains("idle"));

    let projection = control.projection(&session.session_id).unwrap();
    assert_eq!(projection.messages.len(), 2);
    assert_eq!(projection.messages[0].role, MessageRole::User);
    assert_eq!(projection.messages[1].role, MessageRole::Assistant);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn chat_can_use_command_backed_model() {
    let root = temp_root("chat-command-model");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();

    let args = ChatArgs {
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_command: Some(test_model_command()),
        model_timeout_ms: 30_000,
        model_max_stdout_bytes: 1_048_576,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("hello command\n/exit\n");
    let mut out = Vec::new();
    execute_chat(&control, args, &mut input, &mut out).unwrap();

    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("assistant> command reply"));

    let projection = control.projection(&session.session_id).unwrap();
    assert_eq!(projection.messages.len(), 2);
    assert_message_contains(&projection.messages[1], "command reply");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn chat_command_model_times_out() {
    let root = temp_root("chat-command-timeout");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();

    let args = ChatArgs {
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_command: Some(test_slow_model_command()),
        model_timeout_ms: 25,
        model_max_stdout_bytes: 1_048_576,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("hello timeout\n");
    let mut out = Vec::new();
    let error = execute_chat(&control, args, &mut input, &mut out).unwrap_err();

    assert!(error.to_string().contains("timed out"));
    let projection = control.projection(&session.session_id).unwrap();
    assert_eq!(
        projection.agent_heartbeats.values().next().unwrap().status,
        LifecycleStatus::Failed
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn chat_command_model_rejects_large_stdout() {
    let root = temp_root("chat-command-large-output");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();

    let args = ChatArgs {
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_command: Some(test_large_output_model_command()),
        model_timeout_ms: 30_000,
        model_max_stdout_bytes: 8,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("hello large output\n");
    let mut out = Vec::new();
    let error = execute_chat(&control, args, &mut input, &mut out).unwrap_err();

    assert!(error.to_string().contains("stdout exceeded 8 bytes"));
    let projection = control.projection(&session.session_id).unwrap();
    assert_eq!(projection.messages.len(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn workspace_watch_renders_registered_agent_once() {
    let root = temp_root("workspace-watch");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    control
        .register_agent(RegisterAgentRequest::new(
            session.session_id.clone(),
            "researcher",
            "research",
            "Research",
        ))
        .unwrap();
    let task = control
        .create_task(
            CreateTaskRequest::new(session.session_id.clone(), "Map repo").with_lane("research"),
        )
        .unwrap();
    control
        .record_agent_heartbeat(
            AgentHeartbeatRequest::new(
                session.session_id.clone(),
                "researcher",
                LifecycleStatus::Running,
            )
            .with_lane("research")
            .with_task(task.task_id),
        )
        .unwrap();

    let args = WorkspaceArgs {
        command: WorkspaceCommand::Watch(WorkspaceWatchArgs {
            session_id: session.session_id.0.to_string(),
            no_color: true,
            no_clear: true,
            interval_ms: 1,
            ticks: Some(1),
        }),
    };
    let mut out = Vec::new();
    execute_workspace(&control, args, &mut out).unwrap();

    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("ESSENCE AGENT // STAR OFFICE"));
    assert!(rendered.contains("researcher"));
    assert!(rendered.contains("running"));
    assert!(rendered.contains("Map repo"));

    let _ = fs::remove_dir_all(root);
}

fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("essence-cli-{label}-{}", Uuid::new_v4()))
}

fn assert_message_contains(message: &MessagePayload, expected: &str) {
    let text = message.content.iter().find_map(|content| match content {
        ContentBlock::Text { text } => Some(text.as_str()),
        _ => None,
    });
    assert!(text.is_some_and(|text| text.contains(expected)));
}

fn test_model_command() -> String {
    #[cfg(windows)]
    {
        "$input | Out-Null; 'command reply'".to_string()
    }
    #[cfg(not(windows))]
    {
        "cat >/dev/null; printf 'command reply\\n'".to_string()
    }
}

fn test_slow_model_command() -> String {
    #[cfg(windows)]
    {
        "Start-Sleep -Milliseconds 250; 'late reply'".to_string()
    }
    #[cfg(not(windows))]
    {
        "sleep 1; printf 'late reply\\n'".to_string()
    }
}

fn test_large_output_model_command() -> String {
    #[cfg(windows)]
    {
        "$input | Out-Null; 'abcdefghijklmnop'".to_string()
    }
    #[cfg(not(windows))]
    {
        "cat >/dev/null; printf 'abcdefghijklmnop\\n'".to_string()
    }
}
