use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::control::ControlPlane;
use crate::protocol::{AgentHeartbeat, AgentId, SessionId};
use crate::swarm::SwarmRuntime;

#[derive(Debug)]
pub struct SwarmSchedulerHandle {
    running: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl SwarmSchedulerHandle {
    pub fn start(runtime: SwarmRuntime, session_id: SessionId, interval: Duration) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = Arc::clone(&running);
        let join = thread::spawn(move || {
            while thread_running.load(Ordering::SeqCst) {
                let _ = runtime.tick_session(&session_id);
                thread::sleep(interval);
            }
        });

        Self {
            running,
            join: Some(join),
        }
    }

    pub fn stop(mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for SwarmSchedulerHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub fn wait_for_agent_heartbeat(
    control: &ControlPlane,
    session_id: &SessionId,
    agent_id: &AgentId,
    timeout: Duration,
) -> Option<AgentHeartbeat> {
    let started = std::time::Instant::now();
    loop {
        if let Ok(projection) = control.projection(session_id) {
            if let Some(heartbeat) = projection.agent_heartbeats.get(agent_id) {
                return Some(heartbeat.clone());
            }
        }
        if started.elapsed() >= timeout {
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    }
}
