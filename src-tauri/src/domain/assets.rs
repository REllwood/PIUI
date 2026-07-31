use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const PIUI_ASSET_SCHEME: &str = "piui-raster";
pub const PIUI_ASSET_PATH_PREFIX: &str = "/__piui_markdown_asset__/";
pub const MAX_ASSET_BYTES: usize = 10 * 1_048_576;
pub const MAX_ASSET_DIMENSION: u32 = 4_096;
pub const MAX_ASSET_PIXELS: u64 = 16_777_216;
pub const MAX_ASSET_TTL_MS: u64 = 5 * 60_000;
const MAX_ASSETS: usize = 128;
const MAX_TOTAL_ASSET_BYTES: usize = 64 * 1_048_576;
const MAX_TOKEN_ATTEMPTS: usize = 8;
const MAX_WEBVIEW_LABEL_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RasterMime {
    Png,
    Jpeg,
    Webp,
}

impl RasterMime {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "image/png" => Some(Self::Png),
            "image/jpeg" => Some(Self::Jpeg),
            "image/webp" => Some(Self::Webp),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Webp => "webp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueAssetDescriptor {
    pub capability: String,
    pub url: String,
    pub mime: &'static str,
    pub byte_length: usize,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct ResolvedOpaqueAsset {
    pub bytes: Arc<[u8]>,
    pub mime: RasterMime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaqueAssetMetrics {
    pub active_assets: usize,
    pub active_bytes: usize,
    pub registrations: u64,
    pub successful_reads: u64,
    pub rejected_reads: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueAssetError {
    InvalidRaster,
    InvalidLifetime,
    InvalidWebviewLabel,
    CapacityReached,
    ClockUnavailable,
    TokenUnavailable,
    StateUnavailable,
}

impl fmt::Display for OpaqueAssetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRaster => "asset-invalid-raster",
            Self::InvalidLifetime => "asset-invalid-lifetime",
            Self::InvalidWebviewLabel => "asset-invalid-webview-label",
            Self::CapacityReached => "asset-capacity-reached",
            Self::ClockUnavailable => "asset-clock-unavailable",
            Self::TokenUnavailable => "asset-token-unavailable",
            Self::StateUnavailable => "asset-state-unavailable",
        })
    }
}

impl std::error::Error for OpaqueAssetError {}

#[derive(Clone)]
struct AssetEntry {
    owner_webview_label: String,
    path: String,
    bytes: Arc<[u8]>,
    mime: RasterMime,
    expires_at: u64,
}

#[derive(Default)]
struct AssetRegistryState {
    entries: HashMap<String, AssetEntry>,
    total_bytes: usize,
    registrations: u64,
    successful_reads: u64,
    rejected_reads: u64,
}

#[derive(Default)]
pub struct OpaqueAssetRegistry {
    state: Mutex<AssetRegistryState>,
}

impl OpaqueAssetRegistry {
    pub fn register_raster(
        &self,
        owner_webview_label: &str,
        bytes: Vec<u8>,
        claimed_mime: &str,
        lifetime: Duration,
    ) -> Result<OpaqueAssetDescriptor, OpaqueAssetError> {
        let now = epoch_millis()?;
        let lifetime_ms =
            u64::try_from(lifetime.as_millis()).map_err(|_| OpaqueAssetError::InvalidLifetime)?;
        self.register_raster_at(owner_webview_label, bytes, claimed_mime, lifetime_ms, now)
    }

    pub fn resolve_request(
        &self,
        owner_webview_label: &str,
        method: &str,
        path_and_query: &str,
    ) -> Option<ResolvedOpaqueAsset> {
        let now = match epoch_millis() {
            Ok(now) => now,
            Err(_) => {
                self.record_rejected_read();
                return None;
            }
        };
        self.resolve_request_at(owner_webview_label, method, path_and_query, now)
    }

    pub fn metrics(&self) -> Result<OpaqueAssetMetrics, OpaqueAssetError> {
        let state = self.lock_state()?;
        Ok(OpaqueAssetMetrics {
            active_assets: state.entries.len(),
            active_bytes: state.total_bytes,
            registrations: state.registrations,
            successful_reads: state.successful_reads,
            rejected_reads: state.rejected_reads,
        })
    }

    fn register_raster_at(
        &self,
        owner_webview_label: &str,
        bytes: Vec<u8>,
        claimed_mime: &str,
        lifetime_ms: u64,
        now: u64,
    ) -> Result<OpaqueAssetDescriptor, OpaqueAssetError> {
        if !is_valid_webview_label(owner_webview_label) {
            return Err(OpaqueAssetError::InvalidWebviewLabel);
        }
        if lifetime_ms == 0 || lifetime_ms > MAX_ASSET_TTL_MS {
            return Err(OpaqueAssetError::InvalidLifetime);
        }
        let expires_at = now
            .checked_add(lifetime_ms)
            .ok_or(OpaqueAssetError::InvalidLifetime)?;
        let mime = RasterMime::parse(claimed_mime).ok_or(OpaqueAssetError::InvalidRaster)?;
        inspect_raster(&bytes, mime).ok_or(OpaqueAssetError::InvalidRaster)?;

        let mut state = self.lock_state()?;
        prune_expired(&mut state, now);
        if state.entries.len() >= MAX_ASSETS
            || state
                .total_bytes
                .checked_add(bytes.len())
                .is_none_or(|total| total > MAX_TOTAL_ASSET_BYTES)
        {
            return Err(OpaqueAssetError::CapacityReached);
        }

        let (capability, token) = (0..MAX_TOKEN_ATTEMPTS)
            .find_map(|_| {
                let token = Uuid::new_v4().simple().to_string();
                let capability = format!("piui-asset-{token}");
                (!state.entries.contains_key(&capability)).then_some((capability, token))
            })
            .ok_or(OpaqueAssetError::TokenUnavailable)?;
        let path = format!("{PIUI_ASSET_PATH_PREFIX}{token}.{}", mime.extension());
        let byte_length = bytes.len();
        state.total_bytes += byte_length;
        state.registrations = state.registrations.saturating_add(1);
        state.entries.insert(
            capability.clone(),
            AssetEntry {
                owner_webview_label: owner_webview_label.to_owned(),
                path: path.clone(),
                bytes: Arc::<[u8]>::from(bytes),
                mime,
                expires_at,
            },
        );

        Ok(OpaqueAssetDescriptor {
            capability,
            url: format!("{PIUI_ASSET_SCHEME}://localhost{path}"),
            mime: mime.as_str(),
            byte_length,
            expires_at,
        })
    }

    fn resolve_request_at(
        &self,
        owner_webview_label: &str,
        method: &str,
        path_and_query: &str,
        now: u64,
    ) -> Option<ResolvedOpaqueAsset> {
        if !is_valid_webview_label(owner_webview_label) || method != "GET" {
            self.record_rejected_read();
            return None;
        }
        let mut state = match self.lock_state() {
            Ok(state) => state,
            Err(_) => return None,
        };
        prune_expired(&mut state, now);
        let capability = parse_capability_from_request(path_and_query);
        let Some(entry) = capability
            .as_ref()
            .and_then(|candidate| state.entries.get(candidate))
            .filter(|entry| {
                entry.owner_webview_label == owner_webview_label
                    && entry.path == path_and_query
                    && entry.expires_at > now
            })
            .cloned()
        else {
            state.rejected_reads = state.rejected_reads.saturating_add(1);
            return None;
        };
        if inspect_raster(&entry.bytes, entry.mime).is_none() {
            state.rejected_reads = state.rejected_reads.saturating_add(1);
            return None;
        }
        let Some(capability) = capability else {
            state.rejected_reads = state.rejected_reads.saturating_add(1);
            return None;
        };
        let Some(consumed) = state.entries.remove(&capability) else {
            state.rejected_reads = state.rejected_reads.saturating_add(1);
            return None;
        };
        state.total_bytes = state.total_bytes.saturating_sub(consumed.bytes.len());
        state.successful_reads = state.successful_reads.saturating_add(1);
        Some(ResolvedOpaqueAsset {
            bytes: consumed.bytes,
            mime: consumed.mime,
        })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, AssetRegistryState>, OpaqueAssetError> {
        self.state
            .lock()
            .map_err(|_| OpaqueAssetError::StateUnavailable)
    }

    fn record_rejected_read(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.rejected_reads = state.rejected_reads.saturating_add(1);
        }
    }
}

pub fn is_valid_webview_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_WEBVIEW_LABEL_BYTES
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'/' | b'-'))
}

fn epoch_millis() -> Result<u64, OpaqueAssetError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OpaqueAssetError::ClockUnavailable)?;
    u64::try_from(duration.as_millis()).map_err(|_| OpaqueAssetError::ClockUnavailable)
}

fn prune_expired(state: &mut AssetRegistryState, now: u64) {
    let expired = state
        .entries
        .iter()
        .filter_map(|(capability, entry)| {
            (entry.expires_at <= now).then_some((capability.clone(), entry.bytes.len()))
        })
        .collect::<Vec<_>>();
    for (capability, byte_length) in expired {
        state.entries.remove(&capability);
        state.total_bytes = state.total_bytes.saturating_sub(byte_length);
    }
}

fn parse_capability_from_request(path_and_query: &str) -> Option<String> {
    if path_and_query.contains(['?', '#']) || !path_and_query.starts_with(PIUI_ASSET_PATH_PREFIX) {
        return None;
    }
    let name = path_and_query.strip_prefix(PIUI_ASSET_PATH_PREFIX)?;
    let (token, extension) = name.rsplit_once('.')?;
    if token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !matches!(extension, "png" | "jpg" | "webp")
    {
        return None;
    }
    Some(format!("piui-asset-{token}"))
}

fn dimensions_pass(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= MAX_ASSET_DIMENSION
        && height <= MAX_ASSET_DIMENSION
        && u64::from(width) * u64::from(height) <= MAX_ASSET_PIXELS
}

fn inspect_raster(bytes: &[u8], mime: RasterMime) -> Option<(u32, u32)> {
    if bytes.is_empty() || bytes.len() > MAX_ASSET_BYTES {
        return None;
    }
    match mime {
        RasterMime::Png => inspect_png(bytes),
        RasterMime::Jpeg => inspect_jpeg(bytes),
        RasterMime::Webp => inspect_webp(bytes),
    }
}

fn inspect_png(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 33 || bytes.get(..8)? != SIGNATURE {
        return None;
    }
    let mut offset = 8usize;
    let mut dimensions = None;
    let mut chunks = 0usize;
    while offset.checked_add(12)? <= bytes.len() && chunks < 1_024 {
        let length = usize::try_from(u32::from_be_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
        .ok()?;
        let data_start = offset.checked_add(8)?;
        let chunk_end = offset.checked_add(12)?.checked_add(length)?;
        if chunk_end > bytes.len() {
            return None;
        }
        let kind = bytes.get(offset + 4..offset + 8)?;
        if chunks == 0 {
            if kind != b"IHDR" || length != 13 {
                return None;
            }
            let width = u32::from_be_bytes(bytes.get(data_start..data_start + 4)?.try_into().ok()?);
            let height =
                u32::from_be_bytes(bytes.get(data_start + 4..data_start + 8)?.try_into().ok()?);
            if !dimensions_pass(width, height) {
                return None;
            }
            dimensions = Some((width, height));
        }
        offset = chunk_end;
        chunks += 1;
        if kind == b"IEND" {
            return if length == 0 && offset == bytes.len() {
                dimensions
            } else {
                None
            };
        }
    }
    None
}

fn inspect_jpeg(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 4 || bytes.get(..2)? != [0xff, 0xd8] {
        return None;
    }
    let mut offset = 2usize;
    let mut dimensions = None;
    while offset < bytes.len() {
        while bytes.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let marker = *bytes.get(offset)?;
        offset += 1;
        if marker == 0xd9 {
            return dimensions;
        }
        if marker == 0xda {
            return if bytes.get(bytes.len().saturating_sub(2)..) == Some(&[0xff, 0xd9][..]) {
                dimensions
            } else {
                None
            };
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = usize::from(u16::from_be_bytes(
            bytes.get(offset..offset + 2)?.try_into().ok()?,
        ));
        if length < 2 || offset.checked_add(length)? > bytes.len() {
            return None;
        }
        if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            if length < 7 {
                return None;
            }
            let height = u32::from(u16::from_be_bytes(
                bytes.get(offset + 3..offset + 5)?.try_into().ok()?,
            ));
            let width = u32::from(u16::from_be_bytes(
                bytes.get(offset + 5..offset + 7)?.try_into().ok()?,
            ));
            if !dimensions_pass(width, height) {
                return None;
            }
            dimensions = Some((width, height));
        }
        offset += length;
    }
    None
}

fn inspect_webp(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 30
        || bytes.get(..4)? != b"RIFF"
        || usize::try_from(u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?)).ok()?
            != bytes.len().checked_sub(8)?
        || bytes.get(8..12)? != b"WEBP"
    {
        return None;
    }
    let (width, height) = match bytes.get(12..16)? {
        b"VP8X" => (
            read_u24_le(bytes.get(24..27)?)?.checked_add(1)?,
            read_u24_le(bytes.get(27..30)?)?.checked_add(1)?,
        ),
        b"VP8L" if bytes.get(20) == Some(&0x2f) => {
            let bits = u32::from_le_bytes(bytes.get(21..25)?.try_into().ok()?);
            ((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1)
        }
        _ => return None,
    };
    dimensions_pass(width, height).then_some((width, height))
}

fn read_u24_le(bytes: &[u8]) -> Option<u32> {
    Some(
        u32::from(*bytes.first()?)
            | (u32::from(*bytes.get(1)?) << 8)
            | (u32::from(*bytes.get(2)?) << 16),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAFE_PNG: &[u8] = include_bytes!("../../../tests/fixtures/markdown/safe-local.png");

    #[test]
    fn registry_accepts_only_bounded_inspected_rasters_and_exact_opaque_paths() {
        let registry = OpaqueAssetRegistry::default();
        let descriptor = registry
            .register_raster_at("main", SAFE_PNG.to_vec(), "image/png", 30_000, 1_000)
            .expect("valid fixture");
        assert!(descriptor.capability.starts_with("piui-asset-"));
        assert!(descriptor.url.starts_with("piui-raster://localhost/"));
        assert_eq!(descriptor.mime, "image/png");
        assert_eq!(descriptor.byte_length, SAFE_PNG.len());
        assert_eq!(descriptor.expires_at, 31_000);

        let path = descriptor
            .url
            .strip_prefix("piui-raster://localhost")
            .expect("fixed origin");
        let resolved = registry
            .resolve_request_at("main", "GET", path, 2_000)
            .expect("exact path resolves");
        assert_eq!(&*resolved.bytes, SAFE_PNG);
        assert_eq!(resolved.mime, RasterMime::Png);
        assert!(
            registry
                .resolve_request_at("main", "GET", &format!("{path}?x=1"), 2_000)
                .is_none()
        );
        assert!(
            registry
                .resolve_request_at("main", "GET", "/unrelated", 2_000)
                .is_none()
        );

        let metrics = registry.metrics().expect("metrics");
        assert_eq!(metrics.registrations, 1);
        assert_eq!(metrics.active_assets, 0);
        assert_eq!(metrics.active_bytes, 0);
        assert_eq!(metrics.successful_reads, 1);
        assert_eq!(metrics.rejected_reads, 2);
    }

    #[test]
    fn registry_is_exactly_webview_scoped_and_consumes_only_one_successful_get() {
        let registry = OpaqueAssetRegistry::default();
        let descriptor = registry
            .register_raster_at("main", SAFE_PNG.to_vec(), "image/png", 30_000, 1_000)
            .expect("valid fixture");
        let path = descriptor
            .url
            .strip_prefix("piui-raster://localhost")
            .expect("fixed origin");
        let query_path = format!("{path}?probe=1");

        for (label, method, requested_path) in [
            ("secondary", "GET", path),
            ("main", "POST", path),
            ("main", "get", path),
            ("main", "GET", query_path.as_str()),
        ] {
            assert!(
                registry
                    .resolve_request_at(label, method, requested_path, 2_000)
                    .is_none()
            );
            let metrics = registry.metrics().expect("metrics");
            assert_eq!(metrics.active_assets, 1);
            assert_eq!(metrics.active_bytes, SAFE_PNG.len());
            assert_eq!(metrics.successful_reads, 0);
        }

        assert!(
            registry
                .resolve_request_at("main", "GET", path, 2_000)
                .is_some()
        );
        assert!(
            registry
                .resolve_request_at("main", "GET", path, 2_000)
                .is_none(),
            "a consumed capability must not be replayable"
        );
        let metrics = registry.metrics().expect("metrics");
        assert_eq!(metrics.active_assets, 0);
        assert_eq!(metrics.active_bytes, 0);
        assert_eq!(metrics.successful_reads, 1);
        assert_eq!(metrics.rejected_reads, 5);
    }

    #[test]
    fn registry_reinspects_at_consumption_and_serialises_concurrent_reads() {
        use std::sync::Barrier;
        use std::thread;

        let corrupt_registry = OpaqueAssetRegistry::default();
        let corrupt_descriptor = corrupt_registry
            .register_raster_at("main", SAFE_PNG.to_vec(), "image/png", 30_000, 1_000)
            .expect("valid fixture");
        let corrupt_path = corrupt_descriptor
            .url
            .strip_prefix("piui-raster://localhost")
            .expect("fixed origin");
        {
            let mut state = corrupt_registry.lock_state().expect("registry state");
            let entry = state
                .entries
                .get_mut(&corrupt_descriptor.capability)
                .expect("registered entry");
            entry.bytes = Arc::<[u8]>::from(b"not a raster".to_vec());
        }
        assert!(
            corrupt_registry
                .resolve_request_at("main", "GET", corrupt_path, 2_000)
                .is_none(),
            "registration-time inspection must not replace consume-time inspection"
        );

        let registry = Arc::new(OpaqueAssetRegistry::default());
        let descriptor = registry
            .register_raster_at("main", SAFE_PNG.to_vec(), "image/png", 30_000, 1_000)
            .expect("valid fixture");
        let path = descriptor
            .url
            .strip_prefix("piui-raster://localhost")
            .expect("fixed origin")
            .to_owned();
        let barrier = Arc::new(Barrier::new(3));
        let readers = (0..2)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                thread::spawn(move || {
                    barrier.wait();
                    registry
                        .resolve_request_at("main", "GET", &path, 2_000)
                        .is_some()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let successful_reads = readers
            .into_iter()
            .map(|reader| reader.join().expect("reader thread"))
            .filter(|successful| *successful)
            .count();
        assert_eq!(successful_reads, 1);
        let metrics = registry.metrics().expect("metrics");
        assert_eq!(metrics.active_assets, 0);
        assert_eq!(metrics.successful_reads, 1);
        assert_eq!(metrics.rejected_reads, 1);
    }

    #[test]
    fn registry_prunes_expired_bytes_and_rejects_type_confusion_or_invalid_inputs() {
        let registry = OpaqueAssetRegistry::default();
        let descriptor = registry
            .register_raster_at("main", SAFE_PNG.to_vec(), "image/png", 10, 5_000)
            .expect("valid fixture");
        let path = descriptor
            .url
            .strip_prefix("piui-raster://localhost")
            .expect("fixed origin");
        assert!(
            registry
                .resolve_request_at("main", "GET", path, 5_010)
                .is_none()
        );
        assert_eq!(registry.metrics().expect("metrics").active_assets, 0);

        assert_eq!(
            registry.register_raster_at("main", SAFE_PNG.to_vec(), "image/jpeg", 10, 5_000),
            Err(OpaqueAssetError::InvalidRaster)
        );
        assert_eq!(
            registry.register_raster_at("main", SAFE_PNG.to_vec(), "image/png", 0, 5_000),
            Err(OpaqueAssetError::InvalidLifetime)
        );
        assert_eq!(
            registry.register_raster_at(
                "main",
                SAFE_PNG.to_vec(),
                "image/png",
                MAX_ASSET_TTL_MS + 1,
                5_000,
            ),
            Err(OpaqueAssetError::InvalidLifetime)
        );
        let overlong_label = "a".repeat(MAX_WEBVIEW_LABEL_BYTES + 1);
        for label in [
            "",
            "main.window",
            "main window",
            "main@window",
            "é",
            overlong_label.as_str(),
        ] {
            assert_eq!(
                registry.register_raster_at(label, SAFE_PNG.to_vec(), "image/png", 10, 5_000,),
                Err(OpaqueAssetError::InvalidWebviewLabel)
            );
        }
        for label in ["main", "A26_main-window", "window/child:1"] {
            assert!(is_valid_webview_label(label));
        }
    }
}
