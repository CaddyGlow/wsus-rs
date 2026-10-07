//! `ReportEventBatch` fed from the durable [`EventQueue`].
//!
//! Delivery is at-least-once: events are acknowledged only after the server
//! answered `true`. A failure after the request may have been sent leaves the
//! events queued, so they are sent again with the same `EventInstanceID`,
//! which is the server's natural de-duplication key. Within the queue the
//! event instance id is also the dedup key, so enqueueing the same event
//! twice, or again after acknowledgement, never produces a second report.
//! Not validated against a real WSUS.

use super::{engine::SyncEngine, error::SyncError};
use crate::{
    reporting::{AppendOutcome, EventQueue},
    session::{Clock, Service, unix_to_xs},
    transport::{Idempotence, RetryTimer, Transport},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wsus_protocol::{
    identity::UpdateRevision,
    soap::{Presence, XsDateTime},
    wusp::{
        BasicData, ComputerInfo, ComputerTargetIdentifier, DetailedVersion, ExtendedData,
        PrivateData, ProcessorArchitecture, ReportEventBatch, ReportingEvent,
    },
};

/// The detail records of a native-shaped event: `ExtendedData` (the optional
/// `ReplacementStrings` and the `Key=Value` `MiscData` list, next to the client
/// description taken from the session's computer info) and an empty
/// `PrivateData`, which is what a native Windows Update Agent sends with every
/// event (inventory 9.7, 9.10). An event without detail sends neither record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDetail {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replacement_strings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub misc_data: Vec<String>,
}

/// Queue payload of one event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEvent {
    /// Unique per event; also the queue's dedup key.
    pub event_instance_id: Uuid,
    pub sequence_number: i32,
    /// `xs:dateTime` of the event at the client.
    pub time_at_target: String,
    pub namespace_id: i32,
    pub event_id: i16,
    pub source_id: i16,
    pub update: Option<UpdateRevision>,
    pub win32_hresult: i32,
    pub app_name: Option<String>,
    /// Native-shaped `ExtendedData` and `PrivateData`; absent for plain events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<EventDetail>,
}

/// `ProcessorArchitecture` of the reporting records from the registration's
/// `PROCESSOR_ARCHITECTURE` number (`9` AMD64, `0` x86, `6` IA64).
fn reporting_architecture(info: Option<&ComputerInfo>) -> ProcessorArchitecture {
    match info
        .and_then(|i| i.processor_architecture.value())
        .map(String::as_str)
    {
        Some("9") => ProcessorArchitecture::Amd64Compatible,
        Some("0") => ProcessorArchitecture::X86Compatible,
        Some("6") => ProcessorArchitecture::IA64Compatible,
        _ => ProcessorArchitecture::UnknownArchitecture,
    }
}

/// `OSLocaleID` (an LCID) of the registration's locale name; 0 when the name is
/// not one of the few this client knows.
fn locale_id(info: Option<&ComputerInfo>) -> i32 {
    match info.and_then(|i| i.os_locale.value()).map(String::as_str) {
        Some("en-US") => 1033,
        Some("en-GB") => 2057,
        Some("de-DE") => 1031,
        Some("fr-FR") => 1036,
        Some("es-ES") => 3082,
        Some("it-IT") => 1040,
        Some("ja-JP") => 1041,
        _ => 0,
    }
}

impl ReportEvent {
    /// Appends the event to `queue`, de-duplicated by instance id.
    pub fn enqueue(&self, queue: &mut EventQueue) -> Result<AppendOutcome, SyncError> {
        let payload = serde_json::to_value(self)?;
        Ok(queue.append(&self.event_instance_id.hyphenated().to_string(), payload)?)
    }

    fn to_wire(&self, computer: &str, info: Option<&ComputerInfo>) -> Option<ReportingEvent> {
        let (extended_data, private_data) = match &self.detail {
            None => (Presence::Absent, Presence::Absent),
            Some(d) => (
                Presence::Value(ExtendedData {
                    replacement_strings: if d.replacement_strings.is_empty() {
                        Presence::Absent
                    } else {
                        Presence::Value(d.replacement_strings.clone())
                    },
                    misc_data: if d.misc_data.is_empty() {
                        Presence::Absent
                    } else {
                        Presence::Value(d.misc_data.clone())
                    },
                    computer_brand: info
                        .and_then(|i| i.computer_manufacturer.value().cloned())
                        .map_or(Presence::Absent, Presence::Value),
                    computer_model: info
                        .and_then(|i| i.computer_model.value().cloned())
                        .map_or(Presence::Absent, Presence::Value),
                    bios_revision: info
                        .and_then(|i| i.bios_version.value().cloned())
                        .map_or(Presence::Absent, Presence::Value),
                    processor_architecture: reporting_architecture(info),
                    os_version: DetailedVersion {
                        major: info.map_or(0, |i| i.os_major_version),
                        minor: info.map_or(0, |i| i.os_minor_version),
                        build: info.map_or(0, |i| i.os_build_number),
                        revision: 0,
                        service_pack_major: 0,
                        service_pack_minor: 0,
                    },
                    os_locale_id: locale_id(info),
                    device_id: Presence::Absent,
                }),
                Presence::Value(PrivateData {
                    computer_dns_name: Presence::Absent,
                    user_account_name: Presence::Absent,
                }),
            ),
        };
        Some(ReportingEvent {
            basic_data: Presence::Value(BasicData {
                target_id: Presence::Value(ComputerTargetIdentifier {
                    sid: Presence::Value(computer.to_owned()),
                }),
                sequence_number: self.sequence_number,
                time_at_target: XsDateTime::new(&self.time_at_target)?,
                event_instance_id: self.event_instance_id,
                namespace_id: self.namespace_id,
                event_id: self.event_id,
                source_id: self.source_id,
                update_id: self.update.map_or(Presence::Absent, Presence::Value),
                win32_hresult: self.win32_hresult,
                app_name: self
                    .app_name
                    .clone()
                    .map_or(Presence::Absent, Presence::Value),
            }),
            extended_data,
            private_data,
        })
    }
}

/// Outcome of [`SyncEngine::flush_events`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportOutcome {
    pub batches: usize,
    /// Events the server accepted (and that were acknowledged).
    pub delivered: usize,
    /// Events dropped (and acknowledged) because their payload could not be
    /// decoded; they would otherwise block the queue forever.
    pub dropped_invalid: usize,
    /// Events dropped because the server's `AllowedEventIds` excludes them.
    pub dropped_not_allowed: usize,
}

impl<T: Transport, S: RetryTimer, C: Clock> SyncEngine<T, S, C> {
    /// Sends queued events in batches of at most `batch_size`, acknowledging
    /// each batch only after the server accepted it. On any error the failed
    /// batch stays queued.
    pub async fn flush_events(
        &mut self,
        queue: &mut EventQueue,
        batch_size: usize,
    ) -> Result<ReportOutcome, SyncError> {
        self.session.begin_run();
        let mut outcome = ReportOutcome::default();
        let batch_size = batch_size.max(1);
        loop {
            let pending = queue.pending(batch_size);
            if pending.is_empty() {
                return Ok(outcome);
            }
            let computer = self
                .session
                .state()
                .computer_id
                .map(|c| c.0.hyphenated().to_string())
                .unwrap_or_default();
            let allowed: Option<Vec<i32>> = self
                .session
                .server_config()
                .and_then(|c| c.allowed_event_ids.value().cloned())
                .filter(|a| !a.is_empty());
            let info = self.session.config().computer_info.clone();
            let mut events = Vec::new();
            let mut send_seqs = Vec::new();
            let mut drop_seqs = Vec::new();
            for queued in &pending {
                let decoded = serde_json::from_value::<ReportEvent>(queued.payload.clone())
                    .ok()
                    .and_then(|e| e.to_wire(&computer, info.as_ref()).map(|w| (e, w)));
                match decoded {
                    None => {
                        outcome.dropped_invalid += 1;
                        drop_seqs.push(queued.seq);
                    }
                    Some((e, _))
                        if allowed
                            .as_ref()
                            .is_some_and(|a| !a.contains(&i32::from(e.event_id))) =>
                    {
                        outcome.dropped_not_allowed += 1;
                        drop_seqs.push(queued.seq);
                    }
                    Some((_, wire)) => {
                        events.push(wire);
                        send_seqs.push(queued.seq);
                    }
                }
            }
            if !events.is_empty() {
                let now = unix_to_xs(self.session.now_unix());
                let response = self
                    .session
                    .call(
                        Service::Reporting,
                        "ReportEventBatch",
                        Idempotence::NonIdempotent,
                        |cookie, _| ReportEventBatch {
                            cookie: Presence::Value(cookie.clone()),
                            client_time: now.clone(),
                            event_batch: Presence::Value(events.clone()),
                        },
                    )
                    .await?;
                if !response.result {
                    return Err(SyncError::ReportRejected);
                }
                outcome.batches += 1;
                outcome.delivered += send_seqs.len();
            }
            send_seqs.extend(drop_seqs);
            queue.ack(&send_seqs)?;
        }
    }
}
