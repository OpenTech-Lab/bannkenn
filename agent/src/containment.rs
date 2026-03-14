use crate::client::ContainmentActionRow;
use crate::config::{AgentConfig, ContainmentConfig};
use crate::ebpf::events::{BehaviorEvent, BehaviorLevel};
use crate::enforcement::{EnforcementAction, EnforcementDispatcher, EnforcementOutcome};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;

pub const CONTAINMENT_TICK_INTERVAL_SECS: u64 = 5;
const TRANSITION_RATE_LIMIT_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentState {
    Normal,
    Suspicious,
    Throttle,
    Fuse,
}

impl ContainmentState {
    fn rank(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Suspicious => 1,
            Self::Throttle => 2,
            Self::Fuse => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Suspicious => "suspicious",
            Self::Throttle => "throttle",
            Self::Fuse => "fuse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentTransition {
    pub from: ContainmentState,
    pub to: ContainmentState,
    pub at: DateTime<Utc>,
    pub reason: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub watched_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentDecision {
    pub state: ContainmentState,
    pub transition: Option<ContainmentTransition>,
    pub actions: Vec<EnforcementAction>,
    pub outcomes: Vec<EnforcementOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorContainmentResult {
    pub decision: Option<ContainmentDecision>,
    pub applied: bool,
    pub message: String,
}

#[derive(Debug)]
pub struct ContainmentRuntime {
    coordinator: Arc<Mutex<ContainmentCoordinator>>,
    dispatcher: EnforcementDispatcher,
    dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct ContainmentCoordinator {
    config: ContainmentConfig,
    state: ContainmentState,
    last_transition_at: Option<DateTime<Utc>>,
    fuse_release_at: Option<DateTime<Utc>>,
    active_fuse_pid: Option<u32>,
    active_fuse_root: Option<String>,
}

impl ContainmentRuntime {
    pub fn from_agent_config(agent_config: &AgentConfig) -> Option<Self> {
        let config = agent_config.containment.as_ref()?;
        if !config.enabled {
            return None;
        }

        Some(Self {
            coordinator: Arc::new(Mutex::new(ContainmentCoordinator::new(config))),
            dispatcher: EnforcementDispatcher::from_config(config, &agent_config.server_url),
            dry_run: config.dry_run,
        })
    }

    pub async fn handle_event(&self, event: &BehaviorEvent) -> Result<Option<ContainmentDecision>> {
        let decision = {
            let mut coordinator = self.coordinator.lock().await;
            coordinator.handle_event_at(event, Utc::now())
        };

        self.execute(decision).await
    }

    pub async fn tick(&self) -> Result<Option<ContainmentDecision>> {
        let decision = {
            let mut coordinator = self.coordinator.lock().await;
            coordinator.tick_at(Utc::now())
        };

        self.execute(decision).await
    }

    pub async fn apply_operator_action(
        &self,
        action: &ContainmentActionRow,
    ) -> Result<OperatorContainmentResult> {
        let mut result = {
            let mut coordinator = self.coordinator.lock().await;
            coordinator.apply_operator_action_at(action, Utc::now())
        };

        if let Some(decision) = result.decision.take() {
            let decision = self.execute(Some(decision)).await?;
            result.decision = decision;
        }

        Ok(result)
    }

    async fn execute(
        &self,
        decision: Option<ContainmentDecision>,
    ) -> Result<Option<ContainmentDecision>> {
        let Some(mut decision) = decision else {
            return Ok(None);
        };

        if !decision.actions.is_empty() {
            decision.outcomes = self
                .dispatcher
                .execute_all(&decision.actions, self.dry_run)
                .await?;
        }

        Ok(Some(decision))
    }
}

impl ContainmentCoordinator {
    pub fn new(config: &ContainmentConfig) -> Self {
        Self {
            config: config.clone(),
            state: ContainmentState::Normal,
            last_transition_at: None,
            fuse_release_at: None,
            active_fuse_pid: None,
            active_fuse_root: None,
        }
    }

    #[allow(dead_code)]
    pub fn state(&self) -> ContainmentState {
        self.state
    }

    pub fn handle_event_at(
        &mut self,
        event: &BehaviorEvent,
        now: DateTime<Utc>,
    ) -> Option<ContainmentDecision> {
        let target = self.target_state_for_event(event.level);

        if self.state == ContainmentState::Fuse
            && matches!(event.level, BehaviorLevel::FuseCandidate)
        {
            self.refresh_fuse_timer(event, now);
        }

        if target.rank() <= self.state.rank() {
            return None;
        }

        let reason = match target {
            ContainmentState::Suspicious => "suspicious score threshold crossed",
            ContainmentState::Throttle => "throttle score threshold crossed",
            ContainmentState::Fuse => "fuse score threshold crossed",
            ContainmentState::Normal => "containment cleared",
        };

        self.transition_to_at(target, reason.to_string(), event, now)
    }

    pub fn tick_at(&mut self, now: DateTime<Utc>) -> Option<ContainmentDecision> {
        if self.state != ContainmentState::Fuse {
            return None;
        }

        let release_at = self.fuse_release_at?;
        if now < release_at {
            return None;
        }

        if !self.transition_rate_limit_elapsed(now) {
            return None;
        }

        let decay_target = if self.config.throttle_enabled {
            ContainmentState::Throttle
        } else {
            ContainmentState::Suspicious
        };
        let event = synthetic_decay_event(
            self.active_fuse_pid,
            self.active_fuse_root
                .clone()
                .unwrap_or_else(|| "/".to_string()),
            decay_target,
        );
        self.transition_to_at(
            decay_target,
            "auto fuse release timer elapsed".to_string(),
            &event,
            now,
        )
    }

    pub fn apply_operator_action_at(
        &mut self,
        action: &ContainmentActionRow,
        now: DateTime<Utc>,
    ) -> OperatorContainmentResult {
        match action.command_kind.as_str() {
            "trigger_fuse" => self.apply_manual_fuse(action, now),
            "release_fuse" => self.apply_manual_release(action, now),
            _ => OperatorContainmentResult {
                decision: None,
                applied: false,
                message: format!(
                    "unsupported containment action kind '{}'",
                    action.command_kind
                ),
            },
        }
    }

    fn transition_to_at(
        &mut self,
        target: ContainmentState,
        reason: String,
        event: &BehaviorEvent,
        now: DateTime<Utc>,
    ) -> Option<ContainmentDecision> {
        let from = self.state;
        if from == target {
            return None;
        }

        let transition = ContainmentTransition {
            from,
            to: target,
            at: now,
            reason,
            pid: event.pid,
            score: event.score,
            watched_root: event.watched_root.clone(),
        };
        let actions = self.actions_for_transition(from, target, event, now);

        self.state = target;
        self.last_transition_at = Some(now);

        Some(ContainmentDecision {
            state: self.state,
            transition: Some(transition),
            actions,
            outcomes: Vec::new(),
        })
    }

    fn actions_for_transition(
        &mut self,
        from: ContainmentState,
        target: ContainmentState,
        event: &BehaviorEvent,
        now: DateTime<Utc>,
    ) -> Vec<EnforcementAction> {
        match target {
            ContainmentState::Normal | ContainmentState::Suspicious => {
                let mut actions = Vec::new();
                if from == ContainmentState::Fuse {
                    if let Some(pid) = self.active_fuse_pid.take() {
                        actions.push(EnforcementAction::ResumeProcess {
                            pid,
                            watched_root: self
                                .active_fuse_root
                                .take()
                                .unwrap_or_else(|| event.watched_root.clone()),
                        });
                    }
                    self.fuse_release_at = None;
                }
                actions
            }
            ContainmentState::Throttle => {
                let mut actions = Vec::new();

                if from == ContainmentState::Fuse {
                    if let Some(pid) = self.active_fuse_pid.take() {
                        actions.push(EnforcementAction::ResumeProcess {
                            pid,
                            watched_root: self
                                .active_fuse_root
                                .take()
                                .unwrap_or_else(|| event.watched_root.clone()),
                        });
                    }
                    self.fuse_release_at = None;
                }

                actions.push(EnforcementAction::ApplyIoThrottle {
                    pid: event.pid,
                    watched_root: event.watched_root.clone(),
                });
                actions.push(EnforcementAction::ApplyNetworkThrottle {
                    pid: event.pid,
                    watched_root: event.watched_root.clone(),
                });
                actions
            }
            ContainmentState::Fuse => {
                self.refresh_fuse_timer(event, now);
                let mut actions = Vec::new();
                if let Some(pid) = event.pid {
                    actions.push(EnforcementAction::SuspendProcess {
                        pid,
                        watched_root: event.watched_root.clone(),
                    });
                }
                actions
            }
        }
    }

    fn refresh_fuse_timer(&mut self, event: &BehaviorEvent, now: DateTime<Utc>) {
        self.fuse_release_at =
            Some(now + Duration::minutes(self.config.auto_fuse_release_min as i64));
        self.active_fuse_pid = event.pid;
        self.active_fuse_root = Some(event.watched_root.clone());
    }

    fn apply_manual_fuse(
        &mut self,
        action: &ContainmentActionRow,
        now: DateTime<Utc>,
    ) -> OperatorContainmentResult {
        if !self.config.fuse_enabled {
            return OperatorContainmentResult {
                decision: None,
                applied: false,
                message: "manual fuse requested but fuse containment is disabled".to_string(),
            };
        }

        let watched_root = action
            .watched_root
            .clone()
            .or_else(|| self.active_fuse_root.clone())
            .unwrap_or_else(|| "/".to_string());
        let pid = action.pid.or(self.active_fuse_pid);
        let event = synthetic_operator_event(
            pid,
            watched_root.clone(),
            BehaviorLevel::FuseCandidate,
            self.config.fuse_score,
            "manual fuse trigger".to_string(),
            now,
        );

        if self.state == ContainmentState::Fuse {
            self.refresh_fuse_timer(&event, now);
            return OperatorContainmentResult {
                decision: None,
                applied: true,
                message: format!(
                    "fuse already active for {}; refreshed the fuse release timer",
                    watched_root
                ),
            };
        }

        let decision = self.transition_to_at(
            ContainmentState::Fuse,
            "manual fuse trigger requested by operator".to_string(),
            &event,
            now,
        );

        OperatorContainmentResult {
            decision,
            applied: true,
            message: format!("manual fuse triggered for {}", watched_root),
        }
    }

    fn apply_manual_release(
        &mut self,
        action: &ContainmentActionRow,
        now: DateTime<Utc>,
    ) -> OperatorContainmentResult {
        if self.state != ContainmentState::Fuse {
            return OperatorContainmentResult {
                decision: None,
                applied: true,
                message: "fuse was not active; nothing to release".to_string(),
            };
        }

        let target = if self.config.throttle_enabled {
            ContainmentState::Throttle
        } else {
            ContainmentState::Suspicious
        };
        let watched_root = action
            .watched_root
            .clone()
            .or_else(|| self.active_fuse_root.clone())
            .unwrap_or_else(|| "/".to_string());
        let pid = action.pid.or(self.active_fuse_pid);
        let level = match target {
            ContainmentState::Normal | ContainmentState::Suspicious => BehaviorLevel::Suspicious,
            ContainmentState::Throttle => BehaviorLevel::ThrottleCandidate,
            ContainmentState::Fuse => BehaviorLevel::FuseCandidate,
        };
        let event = synthetic_operator_event(
            pid,
            watched_root.clone(),
            level,
            self.config.throttle_score,
            "manual fuse release".to_string(),
            now,
        );
        let decision = self.transition_to_at(
            target,
            "manual fuse release requested by operator".to_string(),
            &event,
            now,
        );

        OperatorContainmentResult {
            decision,
            applied: true,
            message: format!("manual fuse released for {}", watched_root),
        }
    }

    fn target_state_for_event(&self, level: BehaviorLevel) -> ContainmentState {
        match level {
            BehaviorLevel::Observed => self.state,
            BehaviorLevel::Suspicious => ContainmentState::Suspicious,
            BehaviorLevel::ThrottleCandidate => {
                if self.config.throttle_enabled {
                    ContainmentState::Throttle
                } else {
                    ContainmentState::Suspicious
                }
            }
            BehaviorLevel::FuseCandidate => {
                if self.config.fuse_enabled {
                    ContainmentState::Fuse
                } else if self.config.throttle_enabled {
                    ContainmentState::Throttle
                } else {
                    ContainmentState::Suspicious
                }
            }
        }
    }

    fn transition_rate_limit_elapsed(&self, now: DateTime<Utc>) -> bool {
        self.last_transition_at
            .map(|last| now - last >= Duration::seconds(TRANSITION_RATE_LIMIT_SECS))
            .unwrap_or(true)
    }
}

fn synthetic_decay_event(
    pid: Option<u32>,
    watched_root: String,
    state: ContainmentState,
) -> BehaviorEvent {
    let level = match state {
        ContainmentState::Normal | ContainmentState::Suspicious => BehaviorLevel::Suspicious,
        ContainmentState::Throttle => BehaviorLevel::ThrottleCandidate,
        ContainmentState::Fuse => BehaviorLevel::FuseCandidate,
    };

    BehaviorEvent {
        timestamp: Utc::now(),
        source: "containment_state_machine".to_string(),
        watched_root,
        pid,
        process_name: None,
        exe_path: None,
        command_line: None,
        correlation_hits: 0,
        file_ops: Default::default(),
        touched_paths: Vec::new(),
        protected_paths_touched: Vec::new(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
        score: 0,
        reasons: vec!["auto fuse release".to_string()],
        level,
    }
}

fn synthetic_operator_event(
    pid: Option<u32>,
    watched_root: String,
    level: BehaviorLevel,
    score: u32,
    reason: String,
    now: DateTime<Utc>,
) -> BehaviorEvent {
    BehaviorEvent {
        timestamp: now,
        source: "operator_control".to_string(),
        watched_root,
        pid,
        process_name: None,
        exe_path: None,
        command_line: None,
        correlation_hits: 0,
        file_ops: Default::default(),
        touched_paths: Vec::new(),
        protected_paths_touched: Vec::new(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
        score,
        reasons: vec![reason],
        level,
    }
}
