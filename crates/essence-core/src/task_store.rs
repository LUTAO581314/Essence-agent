use std::collections::BTreeMap;

use crate::projection::LedgerProjection;
use crate::protocol::{AgentId, LaneId, LifecycleStatus, TaskId, TaskRecord};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TaskStore {
    tasks: BTreeMap<TaskId, TaskRecord>,
}

impl TaskStore {
    pub fn from_projection(projection: &LedgerProjection) -> Self {
        Self {
            tasks: projection.tasks.clone(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn get(&self, task_id: &TaskId) -> Option<&TaskRecord> {
        self.tasks.get(task_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &TaskRecord> {
        self.tasks.values()
    }

    pub fn by_status(&self, status: LifecycleStatus) -> impl Iterator<Item = &TaskRecord> {
        self.tasks
            .values()
            .filter(move |task| task.status == status)
    }

    pub fn by_lane<'a>(&'a self, lane_id: &'a LaneId) -> impl Iterator<Item = &'a TaskRecord> {
        self.tasks
            .values()
            .filter(move |task| task.lane_id.as_ref() == Some(lane_id))
    }

    pub fn by_assignee<'a>(
        &'a self,
        assignee: &'a AgentId,
    ) -> impl Iterator<Item = &'a TaskRecord> {
        self.tasks
            .values()
            .filter(move |task| task.assignee.as_ref() == Some(assignee))
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::projection::LedgerProjection;
    use crate::protocol::{AgentId, LaneId, LifecycleStatus, SessionId, TaskId, TaskRecord};

    use super::TaskStore;

    #[test]
    fn filters_tasks_by_common_views() {
        let session_id = SessionId(Uuid::new_v4());
        let first_id = TaskId(Uuid::new_v4());
        let second_id = TaskId(Uuid::new_v4());
        let mut projection = LedgerProjection::default();
        projection.tasks.insert(
            first_id.clone(),
            task(
                first_id.clone(),
                session_id.clone(),
                "Implement stream",
                LifecycleStatus::Running,
                Some("ui"),
                Some("agent-a"),
            ),
        );
        projection.tasks.insert(
            second_id.clone(),
            task(
                second_id,
                session_id,
                "Write docs",
                LifecycleStatus::Queued,
                Some("docs"),
                Some("agent-b"),
            ),
        );

        let store = TaskStore::from_projection(&projection);

        assert_eq!(store.len(), 2);
        assert_eq!(store.get(&first_id).unwrap().title, "Implement stream");
        assert_eq!(store.by_status(LifecycleStatus::Running).count(), 1);
        assert_eq!(store.by_lane(&LaneId("ui".to_string())).count(), 1);
        assert_eq!(
            store.by_assignee(&AgentId("agent-a".to_string())).count(),
            1
        );
    }

    fn task(
        task_id: TaskId,
        session_id: SessionId,
        title: impl Into<String>,
        status: LifecycleStatus,
        lane_id: Option<&str>,
        assignee: Option<&str>,
    ) -> TaskRecord {
        let now = OffsetDateTime::now_utc();
        TaskRecord {
            task_id,
            session_id,
            title: title.into(),
            status,
            created_at: now,
            updated_at: now,
            parent_task_id: None,
            lane_id: lane_id.map(|lane_id| LaneId(lane_id.to_string())),
            assignee: assignee.map(|assignee| AgentId(assignee.to_string())),
            metadata: Default::default(),
        }
    }
}
