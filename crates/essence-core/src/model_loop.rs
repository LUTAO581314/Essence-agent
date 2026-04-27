use serde_json::Value;

use crate::control::{ControlError, ControlPlane, StartRunRequest};
use crate::protocol::{EventEnvelope, MessagePayload, RunMeta, SessionId};

#[derive(Debug, thiserror::Error)]
pub enum ModelLoopError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("model completion failed: {0}")]
    Model(String),
}

pub type ModelLoopResult<T> = Result<T, ModelLoopError>;

pub trait ModelClient {
    fn complete(&self, request: ModelRequest) -> Result<ModelResponse, String>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelRequest {
    pub session_id: SessionId,
    pub run: RunMeta,
    pub messages: Vec<MessagePayload>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelResponse {
    pub text: String,
    pub usage: Option<Value>,
    pub stop_reason: Option<String>,
}

impl ModelResponse {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            usage: None,
            stop_reason: None,
        }
    }

    pub fn with_usage(mut self, usage: Value) -> Self {
        self.usage = Some(usage);
        self
    }

    pub fn with_stop_reason(mut self, stop_reason: impl Into<String>) -> Self {
        self.stop_reason = Some(stop_reason.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompletedModelTurn {
    pub user_event: EventEnvelope,
    pub run: RunMeta,
    pub assistant_event: EventEnvelope,
    pub completed_run: RunMeta,
}

#[derive(Debug, Clone)]
pub struct ModelExecutionLoop<M> {
    control: ControlPlane,
    model: M,
}

impl<M> ModelExecutionLoop<M>
where
    M: ModelClient,
{
    pub fn new(control: ControlPlane, model: M) -> Self {
        Self { control, model }
    }

    pub fn control(&self) -> &ControlPlane {
        &self.control
    }

    pub fn run_user_turn(
        &self,
        session_id: SessionId,
        text: impl Into<String>,
    ) -> ModelLoopResult<CompletedModelTurn> {
        let user_event = self.control.submit_user_message(&session_id, text)?;
        let run = self.control.start_run(
            StartRunRequest::user(session_id.clone()).with_input_event(user_event.event_id.clone()),
        )?;
        let messages = self.control.projection(&session_id)?.messages;
        let response = match self.model.complete(ModelRequest {
            session_id: session_id.clone(),
            run: run.clone(),
            messages,
        }) {
            Ok(response) => response,
            Err(error) => {
                self.control.fail_run(&run, error.clone())?;
                return Err(ModelLoopError::Model(error));
            }
        };
        let assistant_event = self.control.append_assistant_message(
            &session_id,
            Some(&run.run_id),
            Some(&run.turn_id),
            response.text,
        )?;
        let completed_run = if let Some(stop_reason) = response.stop_reason {
            self.control
                .complete_run_with_stop_reason(&run, response.usage, stop_reason)?
        } else {
            self.control.complete_run(&run, response.usage)?
        };

        Ok(CompletedModelTurn {
            user_event,
            run,
            assistant_event,
            completed_run,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::control::{ControlPlane, CreateSessionRequest};
    use crate::model_loop::{ModelClient, ModelExecutionLoop, ModelRequest, ModelResponse};
    use crate::protocol::{ContentBlock, LifecycleStatus};

    #[derive(Debug, Clone)]
    struct EchoModel;

    impl ModelClient for EchoModel {
        fn complete(&self, request: ModelRequest) -> Result<ModelResponse, String> {
            let latest_text = request
                .messages
                .last()
                .and_then(|message| message.content.last())
                .and_then(|content| match content {
                    ContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            Ok(ModelResponse::text(format!("echo: {latest_text}"))
                .with_usage(json!({"output_tokens": 3}))
                .with_stop_reason("stop"))
        }
    }

    #[derive(Debug, Clone)]
    struct FailingModel;

    impl ModelClient for FailingModel {
        fn complete(&self, _request: ModelRequest) -> Result<ModelResponse, String> {
            Err("model unavailable".to_string())
        }
    }

    #[test]
    fn records_successful_model_turn() {
        let root = std::env::temp_dir().join(format!("essence-model-loop-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let runtime = ModelExecutionLoop::new(control.clone(), EchoModel);

        let turn = runtime
            .run_user_turn(session.session_id.clone(), "hello")
            .unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let projected_run = projection.runs.get(&turn.run.run_id).unwrap();

        assert_eq!(projection.messages.len(), 2);
        assert_eq!(projected_run.status, LifecycleStatus::Completed);
        assert_eq!(projected_run.usage, Some(json!({"output_tokens": 3})));
        assert_eq!(projected_run.stop_reason.as_deref(), Some("stop"));
        assert_eq!(turn.completed_run.stop_reason.as_deref(), Some("stop"));
        assert_eq!(turn.assistant_event.run_id, Some(turn.run.run_id));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fails_run_when_model_errors() {
        let root = std::env::temp_dir().join(format!("essence-model-loop-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let runtime = ModelExecutionLoop::new(control.clone(), FailingModel);

        let error = runtime
            .run_user_turn(session.session_id.clone(), "hello")
            .unwrap_err();

        let projection = control.projection(&session.session_id).unwrap();
        let run = projection.runs.values().next().unwrap();

        assert!(error.to_string().contains("model unavailable"));
        assert_eq!(run.status, LifecycleStatus::Failed);
        assert_eq!(run.stop_reason.as_deref(), Some("model unavailable"));

        let _ = std::fs::remove_dir_all(root);
    }
}
