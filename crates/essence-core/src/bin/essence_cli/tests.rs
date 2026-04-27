use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use uuid::Uuid;

use super::agent_profile::read_agent_profile;
use super::args::*;
use super::chat::execute_chat;
use super::execute;
use super::model_config::read_model_config;
use super::setup::execute_setup;
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
        agent_profile: None,
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_provider: Some(CliModelProvider::Local),
        model_base_url: None,
        model_api_key_env: None,
        model_command: None,
        model_timeout_ms: 30_000,
        model_max_response_bytes: 1_048_576,
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
        agent_profile: None,
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_provider: Some(CliModelProvider::Command),
        model_base_url: None,
        model_api_key_env: None,
        model_command: Some(test_model_command()),
        model_timeout_ms: 30_000,
        model_max_response_bytes: 1_048_576,
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
fn chat_can_use_openai_compatible_model() {
    let root = temp_root("chat-openai-compatible-model");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    let mock = spawn_mock_chat_server(
        "HTTP/1.1 200 OK",
        r#"{"choices":[{"message":{"content":"http reply"},"finish_reason":"stop"}],"usage":{"completion_tokens":2}}"#
            .to_string(),
    );
    let api_key_env = format!("ESSENCE_TEST_MODEL_API_KEY_{}", Uuid::new_v4().simple());
    std::env::set_var(&api_key_env, "test-secret");

    let args = ChatArgs {
        agent_profile: None,
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: Some("test-chat-model".to_string()),
        model_provider: Some(CliModelProvider::OpenaiCompatible),
        model_base_url: Some(mock.base_url.clone()),
        model_api_key_env: Some(api_key_env.clone()),
        model_command: None,
        model_timeout_ms: 30_000,
        model_max_response_bytes: 1_048_576,
        model_max_stdout_bytes: 1_048_576,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("hello http\n/exit\n");
    let mut out = Vec::new();
    execute_chat(&control, args, &mut input, &mut out).unwrap();
    std::env::remove_var(api_key_env);

    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("assistant> http reply"));

    let captured = mock.requests.recv_timeout(Duration::from_secs(2)).unwrap();
    mock.join.join().unwrap();
    assert!(captured
        .request_line
        .starts_with("POST /v1/chat/completions "));
    assert!(captured
        .headers
        .iter()
        .any(|header| header.eq_ignore_ascii_case("authorization: Bearer test-secret")));
    let body: Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["model"], "test-chat-model");
    assert_eq!(body["stream"], false);
    let messages = body["messages"].as_array().unwrap();
    let latest = messages.last().unwrap();
    assert_eq!(latest["role"], "user");
    assert_eq!(latest["content"], "hello http");

    let projection = control.projection(&session.session_id).unwrap();
    assert_eq!(projection.messages.len(), 2);
    assert_message_contains(&projection.messages[1], "http reply");
    let run = projection.runs.values().next().unwrap();
    assert_eq!(run.usage, Some(serde_json::json!({"completion_tokens": 2})));
    assert_eq!(run.stop_reason.as_deref(), Some("stop"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn setup_writes_pixel_config_and_chat_uses_it() {
    let _env = EnvVarGuard::clear(&[
        "ESSENCE_MODEL_PROVIDER",
        "ESSENCE_MODEL",
        "ESSENCE_MODEL_BASE_URL",
        "ESSENCE_MODEL_API_KEY",
        "OPENAI_API_KEY",
        "ESSENCE_CHAT_MODEL_CMD",
    ]);
    let root = temp_root("setup-model-config");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    let mock = spawn_mock_chat_server(
        "HTTP/1.1 200 OK",
        r#"{"choices":[{"message":{"content":"configured reply"},"finish_reason":"stop"}],"usage":{"completion_tokens":4}}"#
            .to_string(),
    );
    let api_key_env = format!("ESSENCE_TEST_SETUP_API_KEY_{}", Uuid::new_v4().simple());
    std::env::set_var(&api_key_env, "configured-secret");
    let main_prompt = "You are the custom main Essence agent.";

    let setup_args = SetupArgs {
        model_provider: CliModelProvider::OpenaiCompatible,
        model: Some("configured-model".to_string()),
        model_base_url: Some(mock.base_url.clone()),
        model_api_key_env: Some(api_key_env.clone()),
        model_command: None,
        main_agent: Some("main".to_string()),
        main_agent_lane: Some("main".to_string()),
        main_agent_role: Some("Main Operator".to_string()),
        main_agent_prompt: Some(main_prompt.to_string()),
        main_agent_prompt_file: None,
        main_agent_template: None,
        save: true,
        no_color: true,
    };
    let mut setup_out = Vec::new();
    execute_setup(&control, setup_args, &mut setup_out).unwrap();
    let setup_rendered = String::from_utf8(setup_out).unwrap();
    assert!(setup_rendered.contains("ESSENCE AGENT SETUP"));
    assert!(setup_rendered.contains("01 DOWNLOAD"));
    assert!(setup_rendered.contains("02 CONFIGURE"));
    assert!(setup_rendered.contains("03 CHAT"));
    assert!(setup_rendered.contains("04 BOARD"));
    assert!(setup_rendered.contains("main agent"));
    assert!(setup_rendered.contains("PROMPT READY"));
    assert!(setup_rendered.contains("saved"));
    assert!(setup_rendered.contains("saved agent"));

    let stored = read_model_config(&root).unwrap().unwrap();
    assert_eq!(stored.provider.as_deref(), Some("openai-compatible"));
    assert_eq!(stored.model.as_deref(), Some("configured-model"));
    assert_eq!(stored.api_key_env.as_deref(), Some(api_key_env.as_str()));
    let profile = read_agent_profile(&root, "main").unwrap();
    assert_eq!(profile.agent_id, "main");
    assert_eq!(profile.lane, "main");
    assert_eq!(profile.role, "Main Operator");
    assert_eq!(profile.system_prompt.as_deref(), Some(main_prompt));

    let args = ChatArgs {
        agent_profile: None,
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_provider: None,
        model_base_url: None,
        model_api_key_env: None,
        model_command: None,
        model_timeout_ms: 30_000,
        model_max_response_bytes: 1_048_576,
        model_max_stdout_bytes: 1_048_576,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("hello configured setup\n/exit\n");
    let mut out = Vec::new();
    execute_chat(&control, args, &mut input, &mut out).unwrap();
    std::env::remove_var(api_key_env);

    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("agent          main"));
    assert!(rendered.contains("role           Main Operator"));
    assert!(rendered.contains("assistant> configured reply"));

    let captured = mock.requests.recv_timeout(Duration::from_secs(2)).unwrap();
    mock.join.join().unwrap();
    assert!(captured
        .request_line
        .starts_with("POST /v1/chat/completions "));
    let body: Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["model"], "configured-model");
    assert_eq!(body["stream"], false);
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][0]["content"], main_prompt);
    assert_eq!(body["messages"][1]["role"], "user");
    assert_eq!(body["messages"][1]["content"], "hello configured setup");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn setup_rejects_bad_main_agent_inputs_before_writing_config() {
    let root = temp_root("setup-bad-main-agent");
    let control = ControlPlane::new(&root);

    let invalid_agent_args = SetupArgs {
        model_provider: CliModelProvider::OpenaiCompatible,
        model: Some("configured-model".to_string()),
        model_base_url: None,
        model_api_key_env: Some("OPENAI_API_KEY".to_string()),
        model_command: None,
        main_agent: Some("bad id".to_string()),
        main_agent_lane: None,
        main_agent_role: None,
        main_agent_prompt: None,
        main_agent_prompt_file: None,
        main_agent_template: None,
        save: true,
        no_color: true,
    };
    let mut out = Vec::new();
    let error = execute_setup(&control, invalid_agent_args, &mut out).unwrap_err();
    assert!(error.to_string().contains("invalid agent id `bad id`"));
    assert!(read_model_config(&root).unwrap().is_none());

    let unknown_template_args = SetupArgs {
        model_provider: CliModelProvider::OpenaiCompatible,
        model: Some("configured-model".to_string()),
        model_base_url: None,
        model_api_key_env: Some("OPENAI_API_KEY".to_string()),
        model_command: None,
        main_agent: Some("main".to_string()),
        main_agent_lane: None,
        main_agent_role: None,
        main_agent_prompt: None,
        main_agent_prompt_file: None,
        main_agent_template: Some("missing-template".to_string()),
        save: true,
        no_color: true,
    };
    let mut out = Vec::new();
    let error = execute_setup(&control, unknown_template_args, &mut out).unwrap_err();
    assert!(error
        .to_string()
        .contains("agent template `missing-template` is not available"));
    assert!(read_model_config(&root).unwrap().is_none());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn agent_define_rejects_unknown_template() {
    let root = temp_root("agent-unknown-template");
    let cli = Cli {
        root: root.clone(),
        command: Command::Agent(AgentArgs {
            command: AgentCommand::Define(AgentDefineArgs {
                agent_id: "researcher".to_string(),
                template: Some("missing-template".to_string()),
                lane: "research".to_string(),
                role: "Research".to_string(),
                system_prompt: None,
                system_prompt_file: None,
                model_provider: None,
                model: None,
                model_base_url: None,
                model_api_key_env: None,
                model_command: None,
                save: true,
                no_color: true,
            }),
        }),
    };

    let mut out = Vec::new();
    let error = execute(cli, &mut out).unwrap_err();
    assert!(error
        .to_string()
        .contains("agent template `missing-template` is not available"));
    assert!(read_agent_profile(&root, "researcher").is_err());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn agent_templates_hint_includes_required_agent_id() {
    let root = temp_root("agent-templates-hint");
    let cli = Cli {
        root: root.clone(),
        command: Command::Agent(AgentArgs {
            command: AgentCommand::Templates(AgentTemplatesArgs {
                query: Some("research".to_string()),
                category: None,
                limit: 1,
                no_color: true,
            }),
        }),
    };

    let mut out = Vec::new();
    execute(cli, &mut out).unwrap();
    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("agent define --agent-id <id> --template <id> --save"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn agent_profile_saves_prompt_and_chat_uses_it() {
    let _env = EnvVarGuard::clear(&[
        "ESSENCE_MODEL_PROVIDER",
        "ESSENCE_MODEL",
        "ESSENCE_MODEL_BASE_URL",
        "ESSENCE_MODEL_API_KEY",
        "OPENAI_API_KEY",
        "ESSENCE_CHAT_MODEL_CMD",
    ]);
    let root = temp_root("agent-profile");
    let api_key_env = format!("ESSENCE_TEST_AGENT_API_KEY_{}", Uuid::new_v4().simple());
    std::env::set_var(&api_key_env, "agent-secret");
    let prompt = "You are a precise research agent. Reply with compact evidence.";
    let prompt_path = root.join("researcher-prompt.txt");
    fs::create_dir_all(&root).unwrap();
    fs::write(&prompt_path, prompt).unwrap();
    let mock = spawn_mock_chat_server(
        "HTTP/1.1 200 OK",
        r#"{"choices":[{"message":{"content":"profile reply"},"finish_reason":"stop"}]}"#
            .to_string(),
    );

    let define_cli = Cli {
        root: root.clone(),
        command: Command::Agent(AgentArgs {
            command: AgentCommand::Define(AgentDefineArgs {
                agent_id: "researcher".to_string(),
                template: None,
                lane: "research".to_string(),
                role: "Research".to_string(),
                system_prompt: None,
                system_prompt_file: Some(prompt_path.clone()),
                model_provider: Some(CliModelProvider::OpenaiCompatible),
                model: Some("profile-model".to_string()),
                model_base_url: Some(mock.base_url.clone()),
                model_api_key_env: Some(api_key_env.clone()),
                model_command: None,
                save: true,
                no_color: true,
            }),
        }),
    };
    let mut define_out = Vec::new();
    execute(define_cli, &mut define_out).unwrap();
    let define_rendered = String::from_utf8(define_out).unwrap();
    assert!(define_rendered.contains("ESSENCE AGENT PROFILE"));
    assert!(define_rendered.contains("researcher"));
    assert!(define_rendered.contains("PROMPT READY"));
    assert!(define_rendered.contains("saved"));

    let profiles_cli = Cli {
        root: root.clone(),
        command: Command::Agent(AgentArgs {
            command: AgentCommand::Profiles(AgentProfilesArgs { no_color: true }),
        }),
    };
    let mut profiles_out = Vec::new();
    execute(profiles_cli, &mut profiles_out).unwrap();
    let profiles_rendered = String::from_utf8(profiles_out).unwrap();
    assert!(profiles_rendered.contains("ESSENCE AGENT PROFILES"));
    assert!(profiles_rendered.contains("researcher"));

    let profile = read_agent_profile(&root, "researcher").unwrap();
    assert_eq!(profile.agent_id, "researcher");
    assert_eq!(profile.lane, "research");
    assert_eq!(profile.role, "Research");
    assert_eq!(profile.system_prompt, None);
    assert_eq!(
        profile.system_prompt_file.as_deref(),
        Some(prompt_path.to_str().unwrap())
    );

    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    let args = ChatArgs {
        agent_profile: Some("researcher".to_string()),
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_provider: None,
        model_base_url: None,
        model_api_key_env: None,
        model_command: None,
        model_timeout_ms: 30_000,
        model_max_response_bytes: 1_048_576,
        model_max_stdout_bytes: 1_048_576,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("summarize this\n/exit\n");
    let mut out = Vec::new();
    execute_chat(&control, args, &mut input, &mut out).unwrap();
    std::env::remove_var(api_key_env);

    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("agent          researcher"));
    assert!(rendered.contains("assistant> profile reply"));

    let captured = mock.requests.recv_timeout(Duration::from_secs(2)).unwrap();
    mock.join.join().unwrap();
    let body: Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["model"], "profile-model");
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][0]["content"], prompt);
    assert_eq!(body["messages"][1]["role"], "user");
    assert_eq!(body["messages"][1]["content"], "summarize this");

    let projection = control.projection(&session.session_id).unwrap();
    assert!(projection
        .agents
        .keys()
        .any(|agent_id| agent_id.0 == "researcher"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn chat_openai_compatible_model_rejects_large_response() {
    let root = temp_root("chat-openai-large-response");
    let control = ControlPlane::new(&root);
    let session = control
        .create_session(CreateSessionRequest::interactive("."))
        .unwrap();
    let mock = spawn_mock_chat_server(
        "HTTP/1.1 200 OK",
        r#"{"choices":[{"message":{"content":"this response is too large"}}]}"#.to_string(),
    );

    let args = ChatArgs {
        agent_profile: None,
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: Some("test-chat-model".to_string()),
        model_provider: Some(CliModelProvider::OpenaiCompatible),
        model_base_url: Some(mock.base_url.clone()),
        model_api_key_env: None,
        model_command: None,
        model_timeout_ms: 30_000,
        model_max_response_bytes: 8,
        model_max_stdout_bytes: 1_048_576,
        model_max_stderr_bytes: 65_536,
        agent_id: "main".to_string(),
        lane: "main".to_string(),
        role: "CLI Assistant".to_string(),
        no_agent: false,
        no_assistant: false,
        no_color: true,
    };
    let mut input = Cursor::new("hello large response\n");
    let mut out = Vec::new();
    let error = execute_chat(&control, args, &mut input, &mut out).unwrap_err();

    assert!(error
        .to_string()
        .contains("model HTTP response exceeded 8 bytes"));
    let _ = mock.requests.recv_timeout(Duration::from_secs(2)).unwrap();
    mock.join.join().unwrap();
    let projection = control.projection(&session.session_id).unwrap();
    assert_eq!(projection.messages.len(), 1);

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
        agent_profile: None,
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_provider: Some(CliModelProvider::Command),
        model_base_url: None,
        model_api_key_env: None,
        model_command: Some(test_slow_model_command()),
        model_timeout_ms: 25,
        model_max_response_bytes: 1_048_576,
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
        agent_profile: None,
        system_prompt: None,
        system_prompt_file: None,
        session_id: Some(session.session_id.0.to_string()),
        cwd: None,
        title: None,
        model: None,
        model_provider: Some(CliModelProvider::Command),
        model_base_url: None,
        model_api_key_env: None,
        model_command: Some(test_large_output_model_command()),
        model_timeout_ms: 30_000,
        model_max_response_bytes: 1_048_576,
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

struct MockChatServer {
    base_url: String,
    requests: Receiver<CapturedHttpRequest>,
    join: thread::JoinHandle<()>,
}

struct CapturedHttpRequest {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

struct EnvVarGuard {
    previous: Vec<(String, Option<String>)>,
}

impl EnvVarGuard {
    fn clear(names: &[&str]) -> Self {
        let previous = names
            .iter()
            .map(|name| {
                let value = std::env::var(name).ok();
                std::env::remove_var(name);
                ((*name).to_string(), value)
            })
            .collect();
        Self { previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (name, value) in &self.previous {
            if let Some(value) = value {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }
    }
}

fn spawn_mock_chat_server(status: &str, body: String) -> MockChatServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, requests) = mpsc::channel();
    let status = status.to_string();
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let request_line = request_line.trim_end_matches(['\r', '\n']).to_string();
        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
            }
            headers.push(line);
        }
        let mut body_bytes = vec![0; content_length];
        reader.read_exact(&mut body_bytes).unwrap();
        let request_body = String::from_utf8_lossy(&body_bytes).to_string();
        sender
            .send(CapturedHttpRequest {
                request_line,
                headers,
                body: request_body,
            })
            .unwrap();

        let response = format!(
            "{status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    MockChatServer {
        base_url: format!("http://{address}/v1"),
        requests,
        join,
    }
}
