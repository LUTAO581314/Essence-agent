use std::collections::BTreeMap;

use crate::projection::LedgerProjection;
use crate::protocol::{ApprovalDecision, ApprovalRequest, LifecycleStatus};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApprovalGrantIndex {
    session_grants_by_subject: BTreeMap<String, Vec<ApprovalRequest>>,
    always_grants_by_subject: BTreeMap<String, Vec<ApprovalRequest>>,
}

impl ApprovalGrantIndex {
    pub fn from_projection(projection: &LedgerProjection) -> Self {
        let mut index = Self::default();
        for approval in projection.approvals.values() {
            index.insert(approval);
        }
        index
    }

    pub fn insert(&mut self, approval: &ApprovalRequest) {
        if approval.status != LifecycleStatus::Completed {
            return;
        }

        match approval.decision {
            Some(ApprovalDecision::ApproveSession) => self
                .session_grants_by_subject
                .entry(approval.subject.clone())
                .or_default()
                .push(approval.clone()),
            Some(ApprovalDecision::ApproveAlways) => {
                self.session_grants_by_subject
                    .entry(approval.subject.clone())
                    .or_default()
                    .push(approval.clone());
                self.always_grants_by_subject
                    .entry(approval.subject.clone())
                    .or_default()
                    .push(approval.clone());
            }
            _ => {}
        }
    }

    pub fn session_grants_for_subject(&self, subject: &str) -> &[ApprovalRequest] {
        self.session_grants_by_subject
            .get(subject)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn always_grants_for_subject(&self, subject: &str) -> &[ApprovalRequest] {
        self.always_grants_by_subject
            .get(subject)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn has_session_grant_for_subject(&self, subject: &str) -> bool {
        !self.session_grants_for_subject(subject).is_empty()
    }

    pub fn has_always_grant_for_subject(&self, subject: &str) -> bool {
        !self.always_grants_for_subject(subject).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, to_value};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::approval_index::ApprovalGrantIndex;
    use crate::projection::LedgerProjection;
    use crate::protocol::{
        ApprovalDecision, ApprovalId, ApprovalRequest, EventEnvelope, EventSource, EventType,
        EventVisibility, LifecycleStatus, RunId, SessionId, ToolCallId,
    };

    #[test]
    fn indexes_reusable_approval_grants_by_subject() {
        let session_id = SessionId(Uuid::new_v4());
        let mut session_grant = approval(session_id.clone(), "code.list");
        session_grant.decision = Some(ApprovalDecision::ApproveSession);
        let mut always_grant = approval(session_id.clone(), "code.index");
        always_grant.decision = Some(ApprovalDecision::ApproveAlways);
        let mut one_shot = approval(session_id.clone(), "code.list");
        one_shot.decision = Some(ApprovalDecision::ApproveOnce);

        let projection = LedgerProjection::replay([
            &event(1, session_id.clone(), session_grant.clone()),
            &event(2, session_id.clone(), always_grant.clone()),
            &event(3, session_id, one_shot),
        ])
        .unwrap();

        let index = ApprovalGrantIndex::from_projection(&projection);

        assert_eq!(
            index.session_grants_for_subject("code.list")[0].approval_id,
            session_grant.approval_id
        );
        assert!(index.has_session_grant_for_subject("code.index"));
        assert_eq!(
            index.always_grants_for_subject("code.index")[0].approval_id,
            always_grant.approval_id
        );
        assert!(index.always_grants_for_subject("code.list").is_empty());
    }

    #[test]
    fn ignores_pending_denied_and_one_shot_approvals() {
        let session_id = SessionId(Uuid::new_v4());
        let mut pending = approval(session_id.clone(), "code.list");
        pending.status = LifecycleStatus::WaitingApproval;
        pending.decision = None;
        let mut denied = approval(session_id.clone(), "code.list");
        denied.status = LifecycleStatus::Failed;
        denied.decision = Some(ApprovalDecision::Deny);
        let mut once = approval(session_id.clone(), "code.list");
        once.decision = Some(ApprovalDecision::ApproveOnce);

        let projection = LedgerProjection::replay([
            &event(1, session_id.clone(), pending),
            &event(2, session_id.clone(), denied),
            &event(3, session_id, once),
        ])
        .unwrap();

        let index = ApprovalGrantIndex::from_projection(&projection);

        assert!(!index.has_session_grant_for_subject("code.list"));
        assert!(!index.has_always_grant_for_subject("code.list"));
    }

    fn approval(session_id: SessionId, subject: &str) -> ApprovalRequest {
        ApprovalRequest {
            approval_id: ApprovalId(Uuid::new_v4()),
            session_id,
            run_id: Some(RunId(Uuid::new_v4())),
            tool_call_id: Some(ToolCallId(Uuid::new_v4())),
            subject: subject.to_string(),
            input: json!({}),
            cwd: None,
            reason: "test".to_string(),
            allowed_decisions: Vec::new(),
            status: LifecycleStatus::Completed,
            expires_at: OffsetDateTime::now_utc(),
            decision: None,
            resolved_at: Some(OffsetDateTime::now_utc()),
            resolved_by: Some("test".to_string()),
        }
    }

    fn event(seq: u64, session_id: SessionId, approval: ApprovalRequest) -> EventEnvelope {
        EventEnvelope::new(
            seq,
            session_id,
            EventType::ApprovalResolved,
            EventSource::System,
            EventVisibility::Audit,
            to_value(approval).unwrap(),
        )
    }
}
