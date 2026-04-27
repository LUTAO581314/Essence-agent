use crate::protocol::{AgentId, LifecycleStatus, TaskRecord};
use crate::task_store::TaskStore;

#[derive(Debug, Clone, PartialEq)]
pub struct ScheduledTask {
    pub task: TaskRecord,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TaskScheduler {
    queued: Vec<ScheduledTask>,
}

impl TaskScheduler {
    pub fn from_task_store(task_store: &TaskStore) -> Self {
        let mut queued = task_store
            .iter()
            .filter(|task| task.status == LifecycleStatus::Queued)
            .cloned()
            .map(|task| ScheduledTask { task })
            .collect::<Vec<_>>();
        queued.sort_by(|left, right| {
            left.task
                .created_at
                .cmp(&right.task.created_at)
                .then_with(|| left.task.task_id.cmp(&right.task.task_id))
        });
        Self { queued }
    }

    pub fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queued.len()
    }

    pub fn next(&self) -> Option<&ScheduledTask> {
        self.queued.first()
    }

    pub fn next_for_assignee(&self, assignee: &AgentId) -> Option<&ScheduledTask> {
        self.queued
            .iter()
            .find(|scheduled| scheduled.task.assignee.as_ref() == Some(assignee))
            .or_else(|| {
                self.queued
                    .iter()
                    .find(|scheduled| scheduled.task.assignee.is_none())
            })
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use crate::projection::LedgerProjection;
    use crate::protocol::{AgentId, LifecycleStatus, SessionId, TaskId, TaskRecord};
    use crate::scheduler::TaskScheduler;
    use crate::task_store::TaskStore;

    #[test]
    fn schedules_queued_tasks_by_creation_time() {
        let session_id = SessionId(Uuid::new_v4());
        let now = OffsetDateTime::now_utc();
        let first_id = TaskId(Uuid::new_v4());
        let second_id = TaskId(Uuid::new_v4());
        let mut projection = LedgerProjection::default();
        projection.tasks.insert(
            second_id.clone(),
            task(
                second_id,
                session_id.clone(),
                "second",
                now + Duration::seconds(5),
                None,
            ),
        );
        projection.tasks.insert(
            first_id.clone(),
            task(first_id, session_id, "first", now, None),
        );

        let scheduler = TaskScheduler::from_task_store(&TaskStore::from_projection(&projection));

        assert_eq!(scheduler.len(), 2);
        assert_eq!(scheduler.next().unwrap().task.title, "first");
    }

    #[test]
    fn prefers_tasks_assigned_to_agent_then_unassigned() {
        let session_id = SessionId(Uuid::new_v4());
        let now = OffsetDateTime::now_utc();
        let mut projection = LedgerProjection::default();
        projection.tasks.insert(
            TaskId(Uuid::new_v4()),
            task(
                TaskId(Uuid::new_v4()),
                session_id.clone(),
                "agent task",
                now,
                Some("agent-a"),
            ),
        );
        projection.tasks.insert(
            TaskId(Uuid::new_v4()),
            task(TaskId(Uuid::new_v4()), session_id, "open task", now, None),
        );

        let scheduler = TaskScheduler::from_task_store(&TaskStore::from_projection(&projection));

        assert_eq!(
            scheduler
                .next_for_assignee(&AgentId("agent-a".to_string()))
                .unwrap()
                .task
                .title,
            "agent task"
        );
        assert_eq!(
            scheduler
                .next_for_assignee(&AgentId("agent-b".to_string()))
                .unwrap()
                .task
                .title,
            "open task"
        );
    }

    fn task(
        task_id: TaskId,
        session_id: SessionId,
        title: impl Into<String>,
        created_at: OffsetDateTime,
        assignee: Option<&str>,
    ) -> TaskRecord {
        TaskRecord {
            task_id,
            session_id,
            title: title.into(),
            status: LifecycleStatus::Queued,
            created_at,
            updated_at: created_at,
            parent_task_id: None,
            lane_id: None,
            assignee: assignee.map(|assignee| AgentId(assignee.to_string())),
            metadata: Default::default(),
        }
    }
}
