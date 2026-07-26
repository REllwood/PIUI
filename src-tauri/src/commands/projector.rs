use crate::protocol::{
    AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION, Envelope, ProtocolKind, validate_envelope,
};
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_JS_SAFE_SEQUENCE: u64 = 9_007_199_254_740_991;
const DEFAULT_MAPPING_CAPACITY: usize = 1_024;
const MAX_STREAMS: usize = 32;
const MAX_STREAM_TEXT_UTF16: usize = 8_192;
const MAX_PUBLIC_ORIGINS: usize = 512;
const MAX_RETAINED_STREAM_ORIGINS: usize = 32;
const RETIRED_FILTER_BITS: usize = 1 << 24;
const RETIRED_FILTER_HASHES: u64 = 8;
const STREAM_ORIGIN_TTL: Duration = Duration::from_secs(600);
const CANCELLATION_ORIGIN_TTL: Duration = Duration::from_secs(2);
const SNAPSHOT_ORIGIN_TTL: Duration = Duration::from_secs(10);
pub(crate) const PROJECTION_REJECTED: &str = "WebView projection rejected";
const PROJECTION_BUSY: &str = "WebView projection busy";
const PROJECTION_EXHAUSTED: &str = "WebView projection sequence exhausted";
const PROJECTION_MAPPING_UNAVAILABLE: &str = "WebView sequence mapping unavailable";
const PROJECTION_ORIGIN_UNAVAILABLE: &str = "WebView operation origin unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicOperationClass {
    Stream,
    Cancellation,
    Snapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublicOrigin {
    class: PublicOperationClass,
    generation: u64,
    expires_at: Instant,
    completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommitAction {
    None,
    RetireOneShot(String),
    CompleteStream(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionMapping {
    ui_sequence: u64,
    generation: u64,
    raw_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReservationOrigin {
    Public {
        id: String,
        class: PublicOperationClass,
    },
    InternalSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InProgress {
    token: u64,
    ui_sequence: u64,
    generation: u64,
    raw_sequence: u64,
    origin: ReservationOrigin,
    stream_dependencies: Vec<String>,
    action: CommitAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenerationLifecycle {
    Inactive { last: u64 },
    Active(u64),
}

struct ProjectorState {
    lifecycle: GenerationLifecycle,
    ui_sequence: u64,
    next_token: u64,
    in_progress: Option<InProgress>,
    mappings: VecDeque<ProjectionMapping>,
    mapping_capacity: usize,
    origins: HashMap<String, PublicOrigin>,
    completed_streams: VecDeque<String>,
    retired_ids: RetiredIdFilter,
}

struct RetiredIdFilter {
    bits: Box<[u64]>,
}

impl RetiredIdFilter {
    fn new() -> Self {
        Self {
            bits: vec![0; RETIRED_FILTER_BITS / u64::BITS as usize].into_boxed_slice(),
        }
    }

    fn insert(&mut self, id: &str) {
        for index in retired_filter_indices(id) {
            self.bits[index / u64::BITS as usize] |= 1_u64 << (index % u64::BITS as usize);
        }
    }

    fn contains(&self, id: &str) -> bool {
        retired_filter_indices(id).all(|index| {
            self.bits[index / u64::BITS as usize] & (1_u64 << (index % u64::BITS as usize)) != 0
        })
    }
}

fn retired_filter_indices(id: &str) -> impl Iterator<Item = usize> {
    let mut first = std::collections::hash_map::DefaultHasher::new();
    0x7069_7569_2d69_6431_u64.hash(&mut first);
    id.hash(&mut first);
    let first = first.finish();
    let mut second = std::collections::hash_map::DefaultHasher::new();
    0x7069_7569_2d69_6432_u64.hash(&mut second);
    id.hash(&mut second);
    let second = second.finish() | 1;
    (0..RETIRED_FILTER_HASHES).map(move |round| {
        first.wrapping_add(round.wrapping_mul(second)) as usize & (RETIRED_FILTER_BITS - 1)
    })
}

/// Application-lifetime final WebView boundary.
///
/// Internal locking is held only while reserving/committing projection state.
/// Delivery runs without a projector, supervisor, restart or acknowledgement
/// lock. A single explicit reservation makes concurrent or re-entrant delivery
/// fail promptly instead of blocking or reusing a UI sequence.
pub(crate) struct WebViewProjector {
    state: Mutex<ProjectorState>,
    delivery_gate: Mutex<()>,
}

impl Default for WebViewProjector {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAPPING_CAPACITY)
    }
}

impl WebViewProjector {
    pub(crate) fn activate_generation(&self, generation: u64) -> Result<bool, String> {
        let _delivery = self.lock_delivery_gate();
        let mut state = self.lock_state();
        match state.lifecycle {
            GenerationLifecycle::Active(active) if generation == active => return Ok(false),
            GenerationLifecycle::Active(active) if generation < active => {
                return Err(PROJECTION_REJECTED.into());
            }
            GenerationLifecycle::Inactive { last } if generation <= last => {
                return Err(PROJECTION_REJECTED.into());
            }
            _ => {}
        }
        retire_generation_state(&mut state);
        state.lifecycle = GenerationLifecycle::Active(generation);
        Ok(true)
    }

    pub(crate) fn deactivate_generation(&self, generation: u64) -> Result<bool, String> {
        let _delivery = self.lock_delivery_gate();
        let mut state = self.lock_state();
        if state.lifecycle != GenerationLifecycle::Active(generation) {
            return Ok(false);
        }
        retire_generation_state(&mut state);
        state.lifecycle = GenerationLifecycle::Inactive { last: generation };
        Ok(true)
    }

    pub(crate) fn project_and_deliver<F, T>(
        &self,
        generation: u64,
        envelope: &Envelope,
        deliver: F,
    ) -> Result<T, String>
    where
        F: FnOnce(&Envelope) -> Result<T, String>,
    {
        self.project_and_deliver_authorised(
            generation,
            envelope,
            || true,
            deliver,
            |_| (false, Ok(())),
        )
    }

    pub(crate) fn project_and_deliver_authorised<P, F, S, T>(
        &self,
        generation: u64,
        envelope: &Envelope,
        pre_delivery: P,
        deliver: F,
        settled: S,
    ) -> Result<T, String>
    where
        P: FnOnce() -> bool,
        F: FnOnce(&Envelope) -> Result<T, String>,
        S: FnOnce(&T) -> (bool, Result<(), String>),
    {
        // Classification stays before payload access, reconstruction or state
        // mutation. No arbitrary ordinary payload is ever cloned.
        if !matches!(
            envelope.kind,
            ProtocolKind::Event | ProtocolKind::Response | ProtocolKind::Ack
        ) {
            return Err(PROJECTION_REJECTED.into());
        }

        // Projection never waits behind another delivery. The gate is held
        // before expiry pruning or reservation mutation, and the callback is
        // restricted by callers to bounded queue acceptance.
        let _delivery = self.try_lock_delivery_gate()?;
        let (projected, token) = {
            let mut state = self.lock_state();
            if state.lifecycle != GenerationLifecycle::Active(generation) {
                return Err(PROJECTION_REJECTED.into());
            }
            prune_expired_origins(&mut state, Instant::now());
            if state.in_progress.is_some() {
                return Err(PROJECTION_BUSY.into());
            }
            let ui_sequence = state
                .ui_sequence
                .checked_add(1)
                .filter(|sequence| *sequence <= MAX_JS_SAFE_SEQUENCE)
                .ok_or_else(|| PROJECTION_EXHAUSTED.to_string())?;
            let (projected, action, origin, stream_dependencies) =
                reconstruct_safe_projection(envelope, ui_sequence, generation, &state.origins)?;
            let token = state
                .next_token
                .checked_add(1)
                .ok_or_else(|| PROJECTION_EXHAUSTED.to_string())?;
            state.next_token = token;
            state.in_progress = Some(InProgress {
                token,
                ui_sequence,
                generation,
                raw_sequence: envelope.sequence,
                origin,
                stream_dependencies,
                action,
            });
            (projected, token)
        };

        let guard = ReservationGuard {
            projector: self,
            token,
            committed: false,
        };
        {
            let state = self.lock_state();
            if state.lifecycle != GenerationLifecycle::Active(generation)
                || !state.in_progress.as_ref().is_some_and(|reservation| {
                    reservation.token == token
                        && reservation.generation == generation
                        && reservation_is_live(reservation, &state, Instant::now())
                })
            {
                return Err(PROJECTION_REJECTED.into());
            }
        }
        if !pre_delivery() {
            return Err(PROJECTION_REJECTED.into());
        }
        let delivery = deliver(&projected)?;
        guard.commit()?;
        let (retire, settlement) = settled(&delivery);
        if retire {
            let correlation = envelope
                .correlation_id
                .as_deref()
                .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
            let mut state = self.lock_state();
            retire_origin(&mut state, correlation);
        }
        settlement?;
        Ok(delivery)
    }

    pub(crate) fn register_public_origin(
        &self,
        id: &str,
        generation: u64,
        class: PublicOperationClass,
    ) -> Result<(), String> {
        if !valid_public_origin_id(id) {
            return Err(PROJECTION_ORIGIN_UNAVAILABLE.into());
        }
        let now = Instant::now();
        let _delivery = self.lock_delivery_gate();
        let mut state = self.lock_state();
        if state.lifecycle != GenerationLifecycle::Active(generation) {
            return Err(PROJECTION_ORIGIN_UNAVAILABLE.into());
        }
        prune_expired_origins(&mut state, now);
        if state.origins.contains_key(id)
            || state.retired_ids.contains(id)
            || state.origins.len() >= MAX_PUBLIC_ORIGINS
        {
            return Err(PROJECTION_ORIGIN_UNAVAILABLE.into());
        }
        state.origins.insert(
            id.to_owned(),
            PublicOrigin {
                class,
                generation,
                expires_at: now + origin_ttl(class),
                completed: false,
            },
        );
        Ok(())
    }

    pub(crate) fn abandon_public_origin(
        &self,
        id: &str,
        generation: u64,
        class: PublicOperationClass,
    ) {
        let _ = self.abandon_public_origin_with_action(id, generation, class, || {});
    }

    pub(crate) fn abandon_public_origin_with_action<F>(
        &self,
        id: &str,
        generation: u64,
        class: PublicOperationClass,
        action: F,
    ) -> bool
    where
        F: FnOnce(),
    {
        let _delivery = self.lock_delivery_gate();
        let mut state = self.lock_state();
        if state.lifecycle != GenerationLifecycle::Active(generation) {
            action();
            return false;
        }
        action();
        if state
            .origins
            .get(id)
            .is_some_and(|origin| origin.class == class && origin.generation == generation)
        {
            retire_origin(&mut state, id);
            true
        } else {
            false
        }
    }

    pub(crate) fn authenticate_ack(
        &self,
        generation: u64,
        envelope: &Envelope,
        expected_waiter: bool,
    ) -> Result<bool, String> {
        if !expected_waiter
            || validate_envelope(envelope).is_err()
            || envelope.kind != ProtocolKind::Ack
            || envelope.error.is_some()
            || envelope.decision_id.is_some()
            || envelope.payload.len() != 1
        {
            return Err(PROJECTION_REJECTED.into());
        }
        let accepted = envelope
            .payload
            .get("accepted")
            .and_then(Value::as_bool)
            .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
        let correlation = envelope
            .correlation_id
            .as_deref()
            .filter(|value| valid_public_origin_id(value))
            .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
        let now = Instant::now();
        let state = self.lock_state();
        if state.lifecycle != GenerationLifecycle::Active(generation)
            || !state.origins.get(correlation).is_some_and(|origin| {
                origin.class == PublicOperationClass::Cancellation
                    && origin.generation == generation
                    && !origin.completed
                    && origin.expires_at > now
            })
        {
            return Err(PROJECTION_REJECTED.into());
        }
        Ok(accepted)
    }

    pub(crate) fn raw_sequence_for(
        &self,
        generation: u64,
        ui_sequence: u64,
    ) -> Result<u64, String> {
        let state = self.lock_state();
        if state.lifecycle != GenerationLifecycle::Active(generation) {
            return Err(PROJECTION_MAPPING_UNAVAILABLE.into());
        }
        if ui_sequence == 0 {
            return Ok(0);
        }
        state
            .mappings
            .iter()
            .rev()
            .find(|mapping| mapping.generation == generation && mapping.ui_sequence == ui_sequence)
            .map(|mapping| mapping.raw_sequence)
            .ok_or_else(|| PROJECTION_MAPPING_UNAVAILABLE.to_string())
    }

    fn commit(&self, token: u64) -> Result<(), String> {
        let mut state = self.lock_state();
        if !state.in_progress.as_ref().is_some_and(|value| {
            value.token == token && state.lifecycle == GenerationLifecycle::Active(value.generation)
        }) {
            return Err(PROJECTION_REJECTED.into());
        }
        let reservation = state.in_progress.take().expect("reservation checked");
        state.ui_sequence = reservation.ui_sequence;
        if state.mappings.len() == state.mapping_capacity {
            state.mappings.pop_front();
        }
        state.mappings.push_back(ProjectionMapping {
            ui_sequence: reservation.ui_sequence,
            generation: reservation.generation,
            raw_sequence: reservation.raw_sequence,
        });
        match reservation.action {
            CommitAction::None => {}
            CommitAction::RetireOneShot(id) => retire_origin(&mut state, &id),
            CommitAction::CompleteStream(id) => {
                if let Some(origin) = state.origins.get_mut(&id)
                    && origin.class == PublicOperationClass::Stream
                {
                    origin.completed = true;
                    origin.expires_at = Instant::now() + STREAM_ORIGIN_TTL;
                    state.completed_streams.retain(|completed| completed != &id);
                    state.completed_streams.push_back(id);
                }
                while state.completed_streams.len() > MAX_RETAINED_STREAM_ORIGINS {
                    if let Some(oldest) = state.completed_streams.pop_front()
                        && state.origins.get(&oldest).is_some_and(|origin| {
                            origin.class == PublicOperationClass::Stream && origin.completed
                        })
                    {
                        retire_origin(&mut state, &oldest);
                    }
                }
            }
        }
        Ok(())
    }

    fn clear_reservation(&self, token: u64) {
        let mut state = self.lock_state();
        if state
            .in_progress
            .as_ref()
            .is_some_and(|value| value.token == token)
        {
            state.in_progress = None;
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ProjectorState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_delivery_gate(&self) -> std::sync::MutexGuard<'_, ()> {
        self.delivery_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn try_lock_delivery_gate(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        match self.delivery_gate.try_lock() {
            Ok(guard) => Ok(guard),
            Err(std::sync::TryLockError::WouldBlock) => Err(PROJECTION_BUSY.into()),
            Err(std::sync::TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        }
    }

    pub(crate) fn emit_if_active<F>(
        &self,
        generation: u64,
        envelope: &Envelope,
        emit: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        if envelope.kind == ProtocolKind::Ack {
            return Err(PROJECTION_REJECTED.into());
        }
        let _delivery = self.lock_delivery_gate();
        let state = self.lock_state();
        let mapped = state.mappings.iter().any(|mapping| {
            mapping.generation == generation && mapping.ui_sequence == envelope.sequence
        });
        if state.lifecycle != GenerationLifecycle::Active(generation)
            || !mapped
            || envelope.id != format!("ui-envelope-{}", envelope.sequence)
        {
            return Err(PROJECTION_REJECTED.into());
        }
        drop(state);
        emit()
    }

    pub(crate) fn emit_ack_if_active<P, F, S>(
        &self,
        generation: u64,
        envelope: &Envelope,
        correlation: &str,
        pending: P,
        emit: F,
        settle: S,
    ) -> Result<(), String>
    where
        P: FnOnce() -> bool,
        F: FnOnce() -> Result<(), String>,
        S: FnOnce() -> Result<(), String>,
    {
        if envelope.kind != ProtocolKind::Ack {
            return Err(PROJECTION_REJECTED.into());
        }
        let _delivery = self.lock_delivery_gate();
        let state = self.lock_state();
        let mapped = state.mappings.iter().any(|mapping| {
            mapping.generation == generation && mapping.ui_sequence == envelope.sequence
        });
        let origin_live = state.origins.get(correlation).is_some_and(|origin| {
            origin.class == PublicOperationClass::Cancellation
                && origin.generation == generation
                && origin.expires_at > Instant::now()
        });
        if state.lifecycle != GenerationLifecycle::Active(generation)
            || !mapped
            || !origin_live
            || envelope.correlation_id.as_deref() != Some(correlation)
            || envelope.id != format!("ui-envelope-{}", envelope.sequence)
            || !pending()
        {
            return Err(PROJECTION_REJECTED.into());
        }
        drop(state);
        emit()?;
        let settlement = settle();
        let mut state = self.lock_state();
        retire_origin(&mut state, correlation);
        settlement
    }

    fn with_capacity(mapping_capacity: usize) -> Self {
        assert!(mapping_capacity > 0);
        Self {
            state: Mutex::new(ProjectorState {
                lifecycle: GenerationLifecycle::Inactive { last: 0 },
                ui_sequence: 0,
                next_token: 0,
                in_progress: None,
                mappings: VecDeque::with_capacity(mapping_capacity),
                mapping_capacity,
                origins: HashMap::with_capacity(MAX_PUBLIC_ORIGINS),
                completed_streams: VecDeque::with_capacity(MAX_RETAINED_STREAM_ORIGINS),
                retired_ids: RetiredIdFilter::new(),
            }),
            delivery_gate: Mutex::new(()),
        }
    }
}

fn origin_ttl(class: PublicOperationClass) -> Duration {
    match class {
        PublicOperationClass::Stream => STREAM_ORIGIN_TTL,
        PublicOperationClass::Cancellation => CANCELLATION_ORIGIN_TTL,
        PublicOperationClass::Snapshot => SNAPSHOT_ORIGIN_TTL,
    }
}

fn reservation_is_live(reservation: &InProgress, state: &ProjectorState, now: Instant) -> bool {
    if state.lifecycle != GenerationLifecycle::Active(reservation.generation) {
        return false;
    }
    let primary_live = match &reservation.origin {
        ReservationOrigin::InternalSnapshot => true,
        ReservationOrigin::Public { id, class } => state.origins.get(id).is_some_and(|origin| {
            origin.class == *class
                && origin.generation == reservation.generation
                && origin.expires_at > now
                && (*class != PublicOperationClass::Stream || !origin.completed)
        }),
    };
    primary_live
        && reservation.stream_dependencies.iter().all(|id| {
            state.origins.get(id).is_some_and(|origin| {
                origin.class == PublicOperationClass::Stream
                    && origin.generation == reservation.generation
                    && origin.expires_at > now
            })
        })
}

fn retire_generation_state(state: &mut ProjectorState) {
    let retired = state.origins.keys().cloned().collect::<Vec<_>>();
    for id in retired {
        retire_origin(state, &id);
    }
    state.in_progress = None;
    state.mappings.clear();
    state.completed_streams.clear();
}

fn prune_expired_origins(state: &mut ProjectorState, now: Instant) {
    let retired = state
        .origins
        .iter()
        .filter(|(_, origin)| origin.expires_at <= now)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in retired {
        retire_origin(state, &id);
    }
}

fn retire_origin(state: &mut ProjectorState, id: &str) {
    if state.origins.remove(id).is_none() {
        return;
    }
    if state.in_progress.as_ref().is_some_and(|reservation| {
        matches!(&reservation.origin, ReservationOrigin::Public { id: origin_id, .. } if origin_id == id)
            || reservation.stream_dependencies.iter().any(|dependency| dependency == id)
    }) {
        state.in_progress = None;
    }
    state.completed_streams.retain(|completed| completed != id);
    state.retired_ids.insert(id);
}

struct ReservationGuard<'a> {
    projector: &'a WebViewProjector,
    token: u64,
    committed: bool,
}

impl ReservationGuard<'_> {
    fn commit(mut self) -> Result<(), String> {
        self.projector.commit(self.token)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.projector.clear_reservation(self.token);
        }
    }
}

fn reconstruct_safe_projection(
    envelope: &Envelope,
    ui_sequence: u64,
    generation: u64,
    origins: &HashMap<String, PublicOrigin>,
) -> Result<(Envelope, CommitAction, ReservationOrigin, Vec<String>), String> {
    if validate_envelope(envelope).is_err()
        || envelope.error.is_some()
        || envelope.decision_id.is_some()
        || !valid_id(&envelope.id)
    {
        return Err(PROJECTION_REJECTED.into());
    }
    let raw_correlation_id = envelope
        .correlation_id
        .as_deref()
        .filter(|value| valid_id(value))
        .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
    let internal_snapshot = raw_correlation_id == AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION;
    let public_origin = if internal_snapshot {
        None
    } else {
        Some(
            origins
                .get(raw_correlation_id)
                .filter(|origin| {
                    origin.generation == generation && origin.expires_at > Instant::now()
                })
                .ok_or_else(|| PROJECTION_REJECTED.to_string())?,
        )
    };
    let correlation_id = if internal_snapshot {
        format!("ui-internal-{ui_sequence}")
    } else {
        raw_correlation_id.to_owned()
    };
    let reservation_origin = if internal_snapshot {
        ReservationOrigin::InternalSnapshot
    } else {
        ReservationOrigin::Public {
            id: raw_correlation_id.to_owned(),
            class: public_origin.expect("public origin checked").class,
        }
    };

    let (payload, action) = match envelope.kind {
        ProtocolKind::Event
            if public_origin.is_some_and(|origin| origin.class == PublicOperationClass::Stream) =>
        {
            let payload = reconstruct_stream_event(&envelope.payload)?;
            let terminal = matches!(
                payload.get("eventType").and_then(Value::as_str),
                Some("stream.complete" | "stream.cancelled")
            );
            let action = if terminal {
                CommitAction::CompleteStream(raw_correlation_id.to_owned())
            } else {
                CommitAction::None
            };
            (payload, action)
        }
        ProtocolKind::Ack
            if public_origin
                .is_some_and(|origin| origin.class == PublicOperationClass::Cancellation) =>
        {
            (reconstruct_ack(&envelope.payload)?, CommitAction::None)
        }
        ProtocolKind::Response
            if internal_snapshot
                || public_origin
                    .is_some_and(|origin| origin.class == PublicOperationClass::Snapshot) =>
        {
            let action = if internal_snapshot {
                CommitAction::None
            } else {
                CommitAction::RetireOneShot(raw_correlation_id.to_owned())
            };
            (
                reconstruct_snapshot(
                    &envelope.payload,
                    envelope.sequence,
                    ui_sequence,
                    generation,
                    origins,
                )?,
                action,
            )
        }
        _ => return Err(PROJECTION_REJECTED.into()),
    };

    let stream_dependencies = if envelope.kind == ProtocolKind::Response {
        envelope
            .payload
            .get("snapshot")
            .and_then(Value::as_object)
            .and_then(|snapshot| snapshot.get("state"))
            .and_then(Value::as_object)
            .and_then(|state| state.get("streams"))
            .and_then(Value::as_object)
            .map(|streams| streams.keys().cloned().collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok((
        Envelope {
            version: 1,
            kind: envelope.kind,
            id: format!("ui-envelope-{ui_sequence}"),
            correlation_id: Some(correlation_id),
            decision_id: None,
            sequence: ui_sequence,
            payload,
            error: None,
        },
        action,
        reservation_origin,
        stream_dependencies,
    ))
}

fn reconstruct_stream_event(payload: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    if payload.len() != 2 {
        return Err(PROJECTION_REJECTED.into());
    }
    let event_type = payload
        .get("eventType")
        .and_then(Value::as_str)
        .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
    let mut safe = Map::new();
    safe.insert("eventType".into(), Value::String(event_type.into()));
    match event_type {
        "stream.delta" => {
            let text = payload
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| text.encode_utf16().count() <= MAX_STREAM_TEXT_UTF16)
                .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
            safe.insert("text".into(), Value::String(text.into()));
        }
        "stream.complete" | "stream.cancelled" => {
            let terminal = payload
                .get("terminal")
                .and_then(Value::as_str)
                .filter(|terminal| {
                    matches!(
                        (event_type, *terminal),
                        ("stream.complete", "complete") | ("stream.cancelled", "cancelled")
                    )
                })
                .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
            safe.insert("terminal".into(), Value::String(terminal.into()));
        }
        _ => return Err(PROJECTION_REJECTED.into()),
    }
    Ok(safe)
}

fn reconstruct_ack(payload: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    if payload.len() != 1 {
        return Err(PROJECTION_REJECTED.into());
    }
    let accepted = payload
        .get("accepted")
        .and_then(Value::as_bool)
        .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
    let mut safe = Map::new();
    safe.insert("accepted".into(), Value::Bool(accepted));
    Ok(safe)
}

fn reconstruct_snapshot(
    payload: &Map<String, Value>,
    raw_outer_sequence: u64,
    ui_sequence: u64,
    generation: u64,
    origins: &HashMap<String, PublicOrigin>,
) -> Result<Map<String, Value>, String> {
    if payload.len() != 1 {
        return Err(PROJECTION_REJECTED.into());
    }
    let snapshot = payload
        .get("snapshot")
        .and_then(Value::as_object)
        .filter(|snapshot| snapshot.len() == 2)
        .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
    snapshot
        .get("sequence")
        .and_then(Value::as_u64)
        .filter(|sequence| *sequence <= raw_outer_sequence && *sequence <= MAX_JS_SAFE_SEQUENCE)
        .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
    let state = snapshot
        .get("state")
        .and_then(Value::as_object)
        .filter(|state| {
            state.len() == 2 && state.get("status") == Some(&Value::String("ready".into()))
        })
        .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
    let streams = state
        .get("streams")
        .and_then(Value::as_object)
        .filter(|streams| streams.len() <= MAX_STREAMS)
        .ok_or_else(|| PROJECTION_REJECTED.to_string())?;

    let mut safe_streams = Map::new();
    for (request_id, stream) in streams {
        if !valid_public_origin_id(request_id)
            || !origins.get(request_id).is_some_and(|origin| {
                origin.class == PublicOperationClass::Stream
                    && origin.generation == generation
                    && origin.expires_at > Instant::now()
            })
        {
            return Err(PROJECTION_REJECTED.into());
        }
        let stream = stream
            .as_object()
            .filter(|stream| (1..=3).contains(&stream.len()))
            .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
        if !stream
            .keys()
            .all(|key| matches!(key.as_str(), "text" | "terminal" | "truncated"))
        {
            return Err(PROJECTION_REJECTED.into());
        }
        let text = stream
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| text.encode_utf16().count() <= MAX_STREAM_TEXT_UTF16)
            .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
        let mut safe_stream = Map::new();
        safe_stream.insert("text".into(), Value::String(text.into()));
        if let Some(terminal) = stream.get("terminal") {
            let terminal = terminal
                .as_str()
                .filter(|value| matches!(*value, "complete" | "cancelled"))
                .ok_or_else(|| PROJECTION_REJECTED.to_string())?;
            safe_stream.insert("terminal".into(), Value::String(terminal.into()));
        }
        if let Some(truncated) = stream.get("truncated") {
            if truncated != &Value::Bool(true) {
                return Err(PROJECTION_REJECTED.into());
            }
            safe_stream.insert("truncated".into(), Value::Bool(true));
        }
        safe_streams.insert(request_id.clone(), Value::Object(safe_stream));
    }

    let mut safe_state = Map::new();
    safe_state.insert("status".into(), Value::String("ready".into()));
    safe_state.insert("streams".into(), Value::Object(safe_streams));
    let mut safe_snapshot = Map::new();
    safe_snapshot.insert("sequence".into(), Value::from(ui_sequence));
    safe_snapshot.insert("state".into(), Value::Object(safe_state));
    let mut safe_payload = Map::new();
    safe_payload.insert("snapshot".into(), Value::Object(safe_snapshot));
    Ok(safe_payload)
}

fn valid_public_origin_id(value: &str) -> bool {
    value.starts_with("web-") && valid_id(value)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    fn envelope(kind: ProtocolKind, id: &str, raw_sequence: u64, payload: Value) -> Envelope {
        Envelope {
            version: 1,
            kind,
            id: id.into(),
            correlation_id: Some("web-stream-1".into()),
            decision_id: None,
            sequence: raw_sequence,
            payload: payload.as_object().cloned().unwrap_or_default(),
            error: None,
        }
    }

    fn delta(raw_sequence: u64, text: &str) -> Envelope {
        envelope(
            ProtocolKind::Event,
            &format!("sidecar-{raw_sequence}"),
            raw_sequence,
            json!({"eventType":"stream.delta","text":text}),
        )
    }

    fn snapshot(raw_sequence: u64) -> Envelope {
        let mut snapshot = envelope(
            ProtocolKind::Response,
            "sidecar-snapshot",
            raw_sequence,
            json!({"snapshot":{"sequence":raw_sequence - 1,"state":{
                "status":"ready","streams":{"web-stream-1":{"text":"safe","terminal":"complete","truncated":true}}
            }}}),
        );
        snapshot.correlation_id = Some("web-snapshot-1".into());
        snapshot
    }

    fn register_stream(projector: &WebViewProjector, generation: u64) {
        projector.activate_generation(generation).unwrap();
        projector
            .register_public_origin("web-stream-1", generation, PublicOperationClass::Stream)
            .unwrap();
    }

    fn register_snapshot(projector: &WebViewProjector, generation: u64) {
        projector.activate_generation(generation).unwrap();
        projector
            .register_public_origin("web-snapshot-1", generation, PublicOperationClass::Snapshot)
            .unwrap();
    }

    #[test]
    fn refused_kinds_and_adversarial_payloads_leave_state_unchanged() {
        let projector = WebViewProjector::default();
        register_stream(&projector, 1);
        register_snapshot(&projector, 1);
        for kind in [
            ProtocolKind::Handshake,
            ProtocolKind::HostRequest,
            ProtocolKind::HostResponse,
            ProtocolKind::Request,
            ProtocolKind::Cancel,
        ] {
            assert!(
                projector
                    .project_and_deliver(
                        1,
                        &envelope(kind, "refused", 9, json!({"key":"secret"})),
                        |_| Ok(())
                    )
                    .is_err()
            );
        }
        let mut outer = snapshot(10);
        outer.payload.insert("rawSequence".into(), Value::from(10));
        outer.payload.insert("afterSequence".into(), Value::from(9));
        let mut nested = snapshot(10);
        nested.payload["snapshot"]["state"]
            .as_object_mut()
            .unwrap()
            .insert("credential".into(), Value::String("runtime-canary".into()));
        let mut stream_secret = snapshot(10);
        stream_secret.payload["snapshot"]["state"]["streams"]["web-stream-1"]
            .as_object_mut()
            .unwrap()
            .insert("token".into(), Value::String("runtime-canary".into()));
        for adversarial in [outer, nested, stream_secret] {
            assert!(
                projector
                    .project_and_deliver(1, &adversarial, |_| Ok(()))
                    .is_err()
            );
        }
        assert!(projector.raw_sequence_for(1, 1).is_err());
    }

    #[test]
    fn correlation_registry_authenticates_classes_and_retires_one_shot_origins() {
        let projector = WebViewProjector::default();
        register_stream(&projector, 1);
        projector
            .register_public_origin("web-cancel-1", 1, PublicOperationClass::Cancellation)
            .unwrap();
        register_snapshot(&projector, 1);
        for forbidden in ["sidecar-37", "ui-internal-9", "rust-snapshot-1-2"] {
            assert!(
                projector
                    .register_public_origin(forbidden, 1, PublicOperationClass::Stream)
                    .is_err()
            );
        }

        let mut forged_ack = envelope(
            ProtocolKind::Ack,
            "sidecar-37",
            37,
            json!({"accepted":true}),
        );
        forged_ack.correlation_id = Some("web-stream-1".into());
        assert!(
            projector
                .project_and_deliver(1, &forged_ack, |_| Ok(()))
                .is_err()
        );
        for forged in ["sidecar-37", "ui-internal-9", "rust-snapshot-1-2"] {
            let mut event = delta(38, "forged");
            event.correlation_id = Some(forged.into());
            assert!(
                projector
                    .project_and_deliver(1, &event, |_| Ok(()))
                    .is_err()
            );
        }

        let mut genuine_ack = forged_ack;
        genuine_ack.correlation_id = Some("web-cancel-1".into());
        let mut ack_capture = None;
        projector
            .project_and_deliver_authorised(
                1,
                &genuine_ack,
                || true,
                |value| {
                    ack_capture = Some(value.clone());
                    Ok(())
                },
                |_| (true, Ok(())),
            )
            .unwrap();
        assert_eq!(
            ack_capture.unwrap().correlation_id.as_deref(),
            Some("web-cancel-1")
        );
        assert!(
            projector
                .project_and_deliver(1, &genuine_ack, |_| Ok(()))
                .is_err()
        );

        let mut unknown_stream = snapshot(40);
        unknown_stream.payload["snapshot"]["state"]["streams"]
            .as_object_mut()
            .unwrap()
            .insert("web-unknown-stream".into(), json!({"text":"unsafe"}));
        assert!(
            projector
                .project_and_deliver(1, &unknown_stream, |_| Ok(()))
                .is_err()
        );
        projector
            .project_and_deliver(1, &snapshot(40), |_| Ok(()))
            .unwrap();

        let terminal = envelope(
            ProtocolKind::Event,
            "sidecar-terminal",
            41,
            json!({"eventType":"stream.complete","terminal":"complete"}),
        );
        projector
            .project_and_deliver(1, &terminal, |_| Ok(()))
            .unwrap();
        assert!(
            projector
                .register_public_origin("web-cancel-1", 1, PublicOperationClass::Cancellation,)
                .is_err()
        );
        assert!(
            projector
                .register_public_origin("web-snapshot-1", 1, PublicOperationClass::Snapshot)
                .is_err()
        );
    }

    #[test]
    fn origin_expiry_abandonment_restart_and_bloom_filter_recover_capacity() {
        let projector = WebViewProjector::default();
        projector.activate_generation(1).unwrap();
        projector
            .register_public_origin("web-expiring-1", 1, PublicOperationClass::Snapshot)
            .unwrap();
        {
            let mut state = projector.lock_state();
            state.origins.get_mut("web-expiring-1").unwrap().expires_at = Instant::now();
        }
        projector
            .register_public_origin("web-after-expiry", 1, PublicOperationClass::Snapshot)
            .unwrap();
        assert!(
            projector
                .register_public_origin("web-expiring-1", 1, PublicOperationClass::Snapshot)
                .is_err()
        );
        projector.abandon_public_origin("web-after-expiry", 1, PublicOperationClass::Snapshot);
        for (id, class) in [
            (
                "web-oldest-cancellation",
                PublicOperationClass::Cancellation,
            ),
            ("web-oldest-snapshot", PublicOperationClass::Snapshot),
        ] {
            projector.register_public_origin(id, 1, class).unwrap();
            projector.abandon_public_origin(id, 1, class);
        }

        for index in 0..20_000 {
            let id = format!("web-abandoned-{index}");
            projector
                .register_public_origin(&id, 1, PublicOperationClass::Cancellation)
                .unwrap();
            projector.abandon_public_origin(&id, 1, PublicOperationClass::Cancellation);
        }
        assert!(
            projector
                .register_public_origin(
                    "web-abandoned-19999",
                    1,
                    PublicOperationClass::Cancellation,
                )
                .is_err()
        );
        for (id, class) in [
            ("web-expiring-1", PublicOperationClass::Snapshot),
            (
                "web-oldest-cancellation",
                PublicOperationClass::Cancellation,
            ),
            ("web-oldest-snapshot", PublicOperationClass::Snapshot),
        ] {
            assert!(projector.register_public_origin(id, 1, class).is_err());
        }
        projector
            .register_public_origin("web-healthy-after-abandon", 1, PublicOperationClass::Stream)
            .unwrap();

        projector
            .register_public_origin("web-old-generation", 1, PublicOperationClass::Stream)
            .unwrap();
        projector.activate_generation(2).unwrap();
        projector
            .register_public_origin("web-new-generation", 2, PublicOperationClass::Stream)
            .unwrap();
        assert!(
            projector
                .register_public_origin("web-old-generation", 2, PublicOperationClass::Stream)
                .is_err()
        );
        let mut late = delta(50, "late");
        late.correlation_id = Some("web-old-generation".into());
        assert!(projector.project_and_deliver(2, &late, |_| Ok(())).is_err());
        let mut healthy = delta(51, "healthy");
        healthy.correlation_id = Some("web-new-generation".into());
        assert!(
            projector
                .project_and_deliver(2, &healthy, |_| Ok(()))
                .is_ok()
        );
    }

    #[test]
    fn generation_deactivation_linearises_delivery_and_rejects_delayed_stale_callers() {
        let projector = Arc::new(WebViewProjector::default());
        register_stream(&projector, 1);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_projector = Arc::clone(&projector);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let delivery = std::thread::spawn(move || {
            worker_projector.project_and_deliver(1, &delta(1, "generation-one"), |_| {
                worker_entered.wait();
                worker_release.wait();
                Ok(())
            })
        });
        entered.wait();
        let deactivation_projector = Arc::clone(&projector);
        let (deactivated_sender, deactivated_receiver) = std::sync::mpsc::channel();
        let deactivation = std::thread::spawn(move || {
            let result = deactivation_projector.deactivate_generation(1);
            deactivated_sender.send(result).unwrap();
        });
        assert!(matches!(
            deactivated_receiver.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.wait();
        assert!(delivery.join().unwrap().is_ok());
        assert_eq!(
            deactivated_receiver.recv_timeout(Duration::from_secs(1)),
            Ok(Ok(true))
        );
        deactivation.join().unwrap();
        assert!(projector.activate_generation(1).is_err());
        projector.activate_generation(2).unwrap();

        projector
            .register_public_origin("web-generation-two", 2, PublicOperationClass::Stream)
            .unwrap();
        let delayed = Arc::new(Barrier::new(2));
        let delayed_projector = Arc::clone(&projector);
        let delayed_worker = Arc::clone(&delayed);
        let stale_registration = std::thread::spawn(move || {
            delayed_worker.wait();
            delayed_projector.register_public_origin(
                "web-delayed-generation-one",
                1,
                PublicOperationClass::Stream,
            )
        });
        delayed.wait();
        assert!(stale_registration.join().unwrap().is_err());
        let mut stale = delta(2, "stale");
        stale.correlation_id = Some("web-stream-1".into());
        let mut stale_delivered = false;
        assert!(
            projector
                .project_and_deliver(1, &stale, |_| {
                    stale_delivered = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!stale_delivered);
        let mut current = delta(3, "current");
        current.correlation_id = Some("web-generation-two".into());
        assert!(
            projector
                .project_and_deliver(2, &current, |_| Ok(()))
                .is_ok()
        );
    }

    #[test]
    fn expiry_pruning_cannot_mutate_while_an_initial_projection_holds_delivery_gate() {
        let projector = Arc::new(WebViewProjector::default());
        register_stream(&projector, 1);
        projector
            .register_public_origin(
                "web-expired-during-delivery",
                1,
                PublicOperationClass::Snapshot,
            )
            .unwrap();
        projector
            .lock_state()
            .origins
            .get_mut("web-expired-during-delivery")
            .unwrap()
            .expires_at = Instant::now();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let delivery_projector = Arc::clone(&projector);
        let delivery_entered = Arc::clone(&entered);
        let delivery_release = Arc::clone(&release);
        let delivery = std::thread::spawn(move || {
            delivery_projector.project_and_deliver(1, &delta(1, "safe"), |_| {
                delivery_entered.wait();
                delivery_release.wait();
                Ok(())
            })
        });
        entered.wait();
        let pruning_projector = Arc::clone(&projector);
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let pruning = std::thread::spawn(move || {
            let result = pruning_projector.register_public_origin(
                "web-after-prune",
                1,
                PublicOperationClass::Snapshot,
            );
            done_sender.send(result).unwrap();
        });
        assert!(matches!(
            done_receiver.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.wait();
        delivery.join().unwrap().unwrap();
        assert_eq!(
            done_receiver.recv_timeout(Duration::from_secs(1)),
            Ok(Ok(()))
        );
        pruning.join().unwrap();
        assert_eq!(projector.raw_sequence_for(1, 1), Ok(1));
    }

    #[test]
    fn hidden_raw_gaps_resequence_and_failure_or_panic_do_not_consume() {
        let projector = WebViewProjector::default();
        register_stream(&projector, 7);
        let mut delivered = Vec::new();
        projector
            .project_and_deliver(7, &delta(4, "one"), |value| {
                delivered.push(value.clone());
                Ok(())
            })
            .unwrap();
        assert!(
            projector
                .project_and_deliver(7, &delta(9, "two"), |_| {
                    Err::<(), String>("delivery failed".into())
                })
                .is_err()
        );
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = projector.project_and_deliver(7, &delta(9, "two"), |_| -> Result<(), String> {
                panic!("delivery panic")
            });
        }));
        assert!(panic_result.is_err());
        projector
            .project_and_deliver(7, &delta(9, "two"), |value| {
                delivered.push(value.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            delivered
                .iter()
                .map(|value| value.sequence)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(delivered[0].id, "ui-envelope-1");
        assert_eq!(delivered[1].id, "ui-envelope-2");
        assert_eq!(delivered[0].correlation_id.as_deref(), Some("web-stream-1"));
        assert_eq!(delivered[1].correlation_id.as_deref(), Some("web-stream-1"));
        assert!(
            !serde_json::to_string(&delivered)
                .unwrap()
                .contains("sidecar-")
        );
        assert_eq!(projector.raw_sequence_for(7, 1), Ok(4));
        assert_eq!(projector.raw_sequence_for(7, 2), Ok(9));
    }

    #[test]
    fn snapshot_is_reconstructed_with_only_safe_ui_coordinates() {
        let projector = WebViewProjector::default();
        register_stream(&projector, 3);
        register_snapshot(&projector, 3);
        let mut captured = None;
        projector
            .project_and_deliver(3, &snapshot(18), |value| {
                captured = Some(value.clone());
                Ok(())
            })
            .unwrap();
        let captured = captured.unwrap();
        assert_eq!(captured.sequence, 1);
        assert_eq!(captured.id, "ui-envelope-1");
        assert_eq!(captured.correlation_id.as_deref(), Some("web-snapshot-1"));
        assert_eq!(captured.payload["snapshot"]["sequence"], 1);
        let encoded = serde_json::to_string(&captured).unwrap();
        for forbidden in [
            "rawSequence",
            "afterSequence",
            "credential",
            "token",
            "secret",
            "sidecar-",
            "rust-",
        ] {
            assert!(!encoded.contains(forbidden));
        }

        let mut internal_snapshot = snapshot(19);
        internal_snapshot.id = "sidecar-19".into();
        internal_snapshot.correlation_id = Some(AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION.into());
        let mut internal_captured = None;
        projector
            .project_and_deliver(3, &internal_snapshot, |value| {
                internal_captured = Some(value.clone());
                Ok(())
            })
            .unwrap();
        let internal_captured = internal_captured.unwrap();
        assert_eq!(internal_captured.id, "ui-envelope-2");
        assert_eq!(
            internal_captured.correlation_id.as_deref(),
            Some("ui-internal-2")
        );
        let encoded = serde_json::to_string(&internal_captured).unwrap();
        assert!(!encoded.contains("sidecar-19"));
        assert!(!encoded.contains(AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION));
    }

    #[test]
    fn concurrent_and_reentrant_projection_fail_promptly_while_lookup_remains_available() {
        let projector = Arc::new(WebViewProjector::default());
        register_stream(&projector, 1);
        projector
            .project_and_deliver(1, &delta(1, "first"), |_| Ok(()))
            .unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_projector = Arc::clone(&projector);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let worker = std::thread::spawn(move || {
            worker_projector.project_and_deliver(1, &delta(2, "held"), |_| {
                worker_entered.wait();
                worker_release.wait();
                Ok(())
            })
        });
        entered.wait();
        assert_eq!(projector.raw_sequence_for(1, 1), Ok(1));
        let started = Instant::now();
        assert_eq!(
            projector.project_and_deliver(1, &delta(3, "concurrent"), |_| Ok(())),
            Err(PROJECTION_BUSY.into())
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        let reentrant = projector.project_and_deliver(1, &delta(3, "reentrant"), |_| Ok(()));
        assert_eq!(reentrant, Err(PROJECTION_BUSY.into()));
        release.wait();
        assert!(worker.join().unwrap().is_ok());
        assert_eq!(projector.raw_sequence_for(1, 2), Ok(2));
    }

    #[test]
    fn direct_reentry_from_callback_is_rejected_without_deadlock() {
        let projector = WebViewProjector::default();
        register_stream(&projector, 1);
        projector
            .project_and_deliver(1, &delta(1, "outer"), |_| {
                assert_eq!(
                    projector.project_and_deliver(1, &delta(2, "inner"), |_| Ok(())),
                    Err(PROJECTION_BUSY.into())
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(projector.raw_sequence_for(1, 1), Ok(1));
    }

    #[test]
    fn mapping_is_generation_bound_and_fails_closed_when_evicted() {
        let projector = WebViewProjector::with_capacity(2);
        register_stream(&projector, 4);
        assert_eq!(projector.raw_sequence_for(4, 0), Ok(0));
        for raw_sequence in [10, 20, 30] {
            projector
                .project_and_deliver(4, &delta(raw_sequence, "safe"), |_| Ok(()))
                .unwrap();
        }
        assert!(projector.raw_sequence_for(4, 1).is_err());
        assert_eq!(projector.raw_sequence_for(4, 2), Ok(20));
        assert_eq!(projector.raw_sequence_for(4, 3), Ok(30));
        assert!(projector.raw_sequence_for(5, 3).is_err());
        assert!(projector.raw_sequence_for(4, 99).is_err());
    }
}
