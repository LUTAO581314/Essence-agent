use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::protocol::{
    EventEnvelope, EventId, EventSource, EventType, EventVisibility, RunId, SessionId, TurnId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventCursor {
    pub after_seq: u64,
}

impl EventCursor {
    pub fn start() -> Self {
        Self { after_seq: 0 }
    }

    pub fn after(after_seq: u64) -> Self {
        Self { after_seq }
    }

    pub fn advance_to(self, event: &UiEvent) -> Self {
        Self {
            after_seq: self.after_seq.max(event.seq),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UiEvent {
    pub event_id: EventId,
    pub seq: u64,
    pub ts: OffsetDateTime,
    pub session_id: SessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<TurnId>,
    pub event_type: EventType,
    pub source: EventSource,
    pub visibility: EventVisibility,
    #[serde(default)]
    pub payload: Value,
}

impl UiEvent {
    pub fn is_user_visible(&self) -> bool {
        matches!(
            self.visibility,
            EventVisibility::User | EventVisibility::MemoryCandidate
        )
    }
}

impl From<&EventEnvelope> for UiEvent {
    fn from(event: &EventEnvelope) -> Self {
        Self {
            event_id: event.event_id.clone(),
            seq: event.seq,
            ts: event.ts,
            session_id: event.session_id.clone(),
            run_id: event.run_id.clone(),
            turn_id: event.turn_id.clone(),
            event_type: event.event_type.clone(),
            source: event.source.clone(),
            visibility: event.visibility.clone(),
            payload: event.payload.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct UiEventStream {
    events: Vec<UiEvent>,
}

impl UiEventStream {
    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a EventEnvelope>) -> Self {
        let mut events = events.into_iter().map(UiEvent::from).collect::<Vec<_>>();
        events.sort_by_key(|event| event.seq);
        Self { events }
    }

    pub fn all(&self) -> &[UiEvent] {
        &self.events
    }

    pub fn after(&self, cursor: EventCursor) -> Vec<UiEvent> {
        self.events
            .iter()
            .filter(|event| event.seq > cursor.after_seq)
            .cloned()
            .collect()
    }

    pub fn user_visible_after(&self, cursor: EventCursor) -> Vec<UiEvent> {
        self.events
            .iter()
            .filter(|event| event.seq > cursor.after_seq && event.is_user_visible())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::protocol::{EventEnvelope, EventSource, EventType, EventVisibility, SessionId};

    use super::{EventCursor, UiEventStream};

    #[test]
    fn streams_events_after_cursor_and_filters_visibility() {
        let session_id = SessionId(Uuid::new_v4());
        let audit = envelope(
            1,
            session_id.clone(),
            EventType::SessionMeta,
            EventVisibility::Audit,
        );
        let user = envelope(
            2,
            session_id.clone(),
            EventType::MessageUser,
            EventVisibility::User,
        );
        let memory = envelope(
            3,
            session_id,
            EventType::MemoryCandidate,
            EventVisibility::MemoryCandidate,
        );
        let stream = UiEventStream::from_events([&memory, &audit, &user]);

        let all_after_first = stream.after(EventCursor::after(1));
        let visible_from_start = stream.user_visible_after(EventCursor::start());

        assert_eq!(stream.all()[0].seq, 1);
        assert_eq!(all_after_first.len(), 2);
        assert_eq!(visible_from_start.len(), 2);
        assert_eq!(visible_from_start[0].event_type, EventType::MessageUser);
        assert_eq!(visible_from_start[1].event_type, EventType::MemoryCandidate);
    }

    fn envelope(
        seq: u64,
        session_id: SessionId,
        event_type: EventType,
        visibility: EventVisibility,
    ) -> EventEnvelope {
        EventEnvelope::new(
            seq,
            session_id,
            event_type,
            EventSource::System,
            visibility,
            json!({}),
        )
    }
}
