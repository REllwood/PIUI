use crate::domain::assets::{OpaqueAssetDescriptor, OpaqueAssetMetrics, OpaqueAssetRegistry};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tauri::{State, Webview};

const SCHEMA_VERSION: u8 = 1;
const OWNER_WEBVIEW_LABEL: &str = "main";
const ASSET_LIFETIME: Duration = Duration::from_secs(4 * 60);
const ENGINE: &str = "javascript-regex";
const HOSTILE_FIXTURE: &str = include_str!("../../../tests/fixtures/markdown/hostile.md");
const SAFE_RASTER: &[u8] = include_bytes!("../../../tests/fixtures/markdown/safe-local.png");

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct A26MarkdownPreparation {
    schema_version: u8,
    test_mode: bool,
    engine: &'static str,
    wasm_modules: u8,
    owner_webview_label: &'static str,
    hostile_fixture_sha256: String,
    raster_fixture_sha256: String,
    asset: OpaqueAssetDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct A26NativeEvidence {
    schema_version: u8,
    test_mode: bool,
    engine: &'static str,
    wasm_modules: u8,
    hostile_fixture_sha256: String,
    raster_fixture_sha256: String,
    prepare_invocations: u64,
    evidence_invocations: u64,
    unexpected_tauri_invocations: u64,
    wrong_webview_invocations: u64,
    asset_registrations: u64,
    asset_successful_reads: u64,
    asset_rejected_reads: u64,
    asset_active_entries: usize,
    asset_active_bytes: usize,
}

pub struct A26MarkdownState {
    assets: Arc<OpaqueAssetRegistry>,
    prepared: AtomicBool,
    prepare_invocations: AtomicU64,
    evidence_invocations: AtomicU64,
    unexpected_tauri_invocations: AtomicU64,
    wrong_webview_invocations: AtomicU64,
}

impl Default for A26MarkdownState {
    fn default() -> Self {
        Self::new(Arc::new(OpaqueAssetRegistry::default()))
    }
}

impl A26MarkdownState {
    pub fn new(assets: Arc<OpaqueAssetRegistry>) -> Self {
        Self {
            assets,
            prepared: AtomicBool::new(false),
            prepare_invocations: AtomicU64::new(0),
            evidence_invocations: AtomicU64::new(0),
            unexpected_tauri_invocations: AtomicU64::new(0),
            wrong_webview_invocations: AtomicU64::new(0),
        }
    }

    pub fn asset_registry(&self) -> Arc<OpaqueAssetRegistry> {
        Arc::clone(&self.assets)
    }

    pub fn record_invoke_entry(
        &self,
        webview_label: &str,
        command: &str,
        payload: &tauri::ipc::InvokeBody,
    ) -> bool {
        let label_allowed = webview_label == OWNER_WEBVIEW_LABEL;
        if webview_label != OWNER_WEBVIEW_LABEL {
            self.wrong_webview_invocations
                .fetch_add(1, Ordering::Relaxed);
        }
        let command_allowed = match command {
            "a26_markdown_prepare" => {
                self.prepare_invocations.fetch_add(1, Ordering::Relaxed);
                true
            }
            "a26_markdown_evidence" => {
                self.evidence_invocations.fetch_add(1, Ordering::Relaxed);
                true
            }
            _ => {
                self.unexpected_tauri_invocations
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        };
        let payload_allowed = matches!(
            payload,
            tauri::ipc::InvokeBody::Json(serde_json::Value::Object(arguments))
                if arguments.is_empty()
        );
        if command_allowed && !payload_allowed {
            self.unexpected_tauri_invocations
                .fetch_add(1, Ordering::Relaxed);
        }
        label_allowed && command_allowed && payload_allowed
    }

    fn prepare_for_label(&self, webview_label: &str) -> Result<A26MarkdownPreparation, String> {
        if webview_label != OWNER_WEBVIEW_LABEL
            || self
                .prepared
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err("a26-markdown-prepare-rejected".into());
        }

        let asset = match self.assets.register_raster(
            OWNER_WEBVIEW_LABEL,
            SAFE_RASTER.to_vec(),
            "image/png",
            ASSET_LIFETIME,
        ) {
            Ok(asset) => asset,
            Err(error) => {
                self.prepared.store(false, Ordering::Release);
                return Err(error.to_string());
            }
        };
        Ok(A26MarkdownPreparation {
            schema_version: SCHEMA_VERSION,
            test_mode: true,
            engine: ENGINE,
            wasm_modules: 0,
            owner_webview_label: OWNER_WEBVIEW_LABEL,
            hostile_fixture_sha256: sha256(HOSTILE_FIXTURE.as_bytes()),
            raster_fixture_sha256: sha256(SAFE_RASTER),
            asset,
        })
    }

    fn native_evidence(&self) -> Result<A26NativeEvidence, String> {
        if !self.prepared.load(Ordering::Acquire) {
            return Err("a26-markdown-evidence-rejected".into());
        }
        let metrics = self
            .assets
            .metrics()
            .map_err(|_| "a26-markdown-evidence-rejected".to_string())?;
        let evidence = self.evidence_from_metrics(metrics);
        if evidence.prepare_invocations != 1
            || evidence.evidence_invocations != 1
            || evidence.unexpected_tauri_invocations != 0
            || evidence.wrong_webview_invocations != 0
            || evidence.asset_registrations != 1
            || evidence.asset_successful_reads != 1
            || evidence.asset_rejected_reads != 0
            || evidence.asset_active_entries != 0
            || evidence.asset_active_bytes != 0
        {
            return Err("a26-markdown-evidence-rejected".into());
        }
        Ok(evidence)
    }

    fn evidence_from_metrics(&self, metrics: OpaqueAssetMetrics) -> A26NativeEvidence {
        A26NativeEvidence {
            schema_version: SCHEMA_VERSION,
            test_mode: true,
            engine: ENGINE,
            wasm_modules: 0,
            hostile_fixture_sha256: sha256(HOSTILE_FIXTURE.as_bytes()),
            raster_fixture_sha256: sha256(SAFE_RASTER),
            prepare_invocations: self.prepare_invocations.load(Ordering::Acquire),
            evidence_invocations: self.evidence_invocations.load(Ordering::Acquire),
            unexpected_tauri_invocations: self.unexpected_tauri_invocations.load(Ordering::Acquire),
            wrong_webview_invocations: self.wrong_webview_invocations.load(Ordering::Acquire),
            asset_registrations: metrics.registrations,
            asset_successful_reads: metrics.successful_reads,
            asset_rejected_reads: metrics.rejected_reads,
            asset_active_entries: metrics.active_assets,
            asset_active_bytes: metrics.active_bytes,
        }
    }
}

#[tauri::command]
pub fn a26_markdown_prepare(
    webview: Webview,
    state: State<'_, A26MarkdownState>,
) -> Result<A26MarkdownPreparation, String> {
    state.prepare_for_label(webview.label())
}

#[tauri::command]
pub fn a26_markdown_evidence(
    state: State<'_, A26MarkdownState>,
) -> Result<A26NativeEvidence, String> {
    state.native_evidence()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_is_main_webview_only_one_shot_and_fixed() {
        let wrong_label = A26MarkdownState::default();
        assert!(wrong_label.prepare_for_label("secondary").is_err());
        assert_eq!(
            wrong_label
                .asset_registry()
                .metrics()
                .expect("asset metrics")
                .registrations,
            0
        );

        let state = A26MarkdownState::default();
        let preparation = state.prepare_for_label("main").expect("preparation");
        assert_eq!(preparation.schema_version, 1);
        assert!(preparation.test_mode);
        assert_eq!(preparation.engine, "javascript-regex");
        assert_eq!(preparation.wasm_modules, 0);
        assert_eq!(preparation.owner_webview_label, "main");
        assert_eq!(
            preparation.hostile_fixture_sha256,
            "9c08397fe195119adb5abf548e5df287c82174918c35b758e150750da26b5ac9"
        );
        assert_eq!(
            preparation.raster_fixture_sha256,
            "431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460"
        );
        assert!(
            preparation
                .asset
                .url
                .starts_with("piui-raster://localhost/")
        );
        assert!(state.prepare_for_label("main").is_err());
        assert_eq!(
            state
                .asset_registry()
                .metrics()
                .expect("asset metrics")
                .registrations,
            1
        );
    }

    #[test]
    fn native_evidence_requires_exact_invoke_and_consumption_counters() {
        let state = A26MarkdownState::default();
        assert!(state.record_invoke_entry(
            "main",
            "a26_markdown_prepare",
            &tauri::ipc::InvokeBody::Json(serde_json::json!({}))
        ));
        let preparation = state.prepare_for_label("main").expect("preparation");
        let path = preparation
            .asset
            .url
            .strip_prefix("piui-raster://localhost")
            .expect("custom protocol path");
        assert!(
            state
                .asset_registry()
                .resolve_request("main", "GET", path)
                .is_some()
        );
        assert!(state.record_invoke_entry(
            "main",
            "a26_markdown_evidence",
            &tauri::ipc::InvokeBody::Json(serde_json::json!({}))
        ));
        let evidence = state.native_evidence().expect("native evidence");
        assert_eq!(evidence.prepare_invocations, 1);
        assert_eq!(evidence.evidence_invocations, 1);
        assert_eq!(evidence.asset_registrations, 1);
        assert_eq!(evidence.asset_successful_reads, 1);
        assert_eq!(evidence.asset_active_entries, 0);
    }

    #[test]
    fn evidence_fails_closed_for_hostile_invokes_wrong_labels_or_unread_assets() {
        let state = A26MarkdownState::default();
        assert!(state.record_invoke_entry(
            "main",
            "a26_markdown_prepare",
            &tauri::ipc::InvokeBody::Json(serde_json::json!({}))
        ));
        state.prepare_for_label("main").expect("preparation");
        assert!(!state.record_invoke_entry(
            "secondary",
            "host_status",
            &tauri::ipc::InvokeBody::Json(serde_json::json!({}))
        ));
        assert!(state.record_invoke_entry(
            "main",
            "a26_markdown_evidence",
            &tauri::ipc::InvokeBody::Json(serde_json::json!({}))
        ));
        assert!(state.native_evidence().is_err());

        let metrics = state.asset_registry().metrics().expect("asset metrics");
        let evidence = state.evidence_from_metrics(metrics);
        assert_eq!(evidence.unexpected_tauri_invocations, 1);
        assert_eq!(evidence.wrong_webview_invocations, 1);
        assert_eq!(evidence.asset_successful_reads, 0);
        assert_eq!(evidence.asset_active_entries, 1);
    }

    #[test]
    fn invoke_entry_rejects_arguments_before_dispatch_and_records_the_attempt() {
        let state = A26MarkdownState::default();
        assert!(!state.record_invoke_entry(
            "main",
            "a26_markdown_prepare",
            &tauri::ipc::InvokeBody::Json(serde_json::json!({ "markdown": "hostile" }))
        ));
        let metrics = state.asset_registry().metrics().expect("asset metrics");
        let evidence = state.evidence_from_metrics(metrics);
        assert_eq!(evidence.prepare_invocations, 1);
        assert_eq!(evidence.unexpected_tauri_invocations, 1);
        assert_eq!(evidence.asset_registrations, 0);
    }

    #[test]
    fn invoke_entry_rejects_raw_payloads_before_dispatch() {
        let state = A26MarkdownState::default();
        assert!(!state.record_invoke_entry(
            "main",
            "a26_markdown_prepare",
            &tauri::ipc::InvokeBody::Raw(Vec::new())
        ));
        let metrics = state.asset_registry().metrics().expect("asset metrics");
        let evidence = state.evidence_from_metrics(metrics);
        assert_eq!(evidence.prepare_invocations, 1);
        assert_eq!(evidence.unexpected_tauri_invocations, 1);
        assert_eq!(evidence.asset_registrations, 0);
    }
}
