use super::super::NativeExportPickerError;
use block2::RcBlock;
use objc2::rc::Retained;
use objc2_app_kit::{NSModalResponse, NSModalResponseOK, NSSavePanel, NSWindow};
use objc2_foundation::{MainThreadMarker, NSString};
use std::path::PathBuf;
use tauri::WebviewWindow;

pub(crate) async fn present(
    window: WebviewWindow,
    default_name: String,
) -> Result<Option<PathBuf>, NativeExportPickerError> {
    let (sender, mut receiver) = tauri::async_runtime::channel(1);
    window
        .with_webview(move |webview| {
            let Some(mtm) = MainThreadMarker::new() else {
                let _ = sender.try_send(Err(NativeExportPickerError::unavailable()));
                return;
            };
            let Some(parent) =
                (unsafe { Retained::<NSWindow>::retain(webview.ns_window().cast()) })
            else {
                let _ = sender.try_send(Err(NativeExportPickerError::unavailable()));
                return;
            };
            let panel = NSSavePanel::savePanel(mtm);
            panel.setCanCreateDirectories(true);
            panel.setNameFieldStringValue(&NSString::from_str(&default_name));
            let completion_panel = panel.clone();
            let completion: RcBlock<dyn Fn(NSModalResponse) + 'static> =
                RcBlock::new(move |response| {
                    let result = if response == NSModalResponseOK {
                        completion_panel
                            .URL()
                            .and_then(|url| url.path())
                            .map(|path| PathBuf::from(path.to_string()))
                            .ok_or_else(NativeExportPickerError::unavailable)
                            .map(Some)
                    } else {
                        Ok(None)
                    };
                    let _ = sender.try_send(result);
                });
            panel.beginSheetModalForWindow_completionHandler(&parent, &completion);
        })
        .map_err(|_| NativeExportPickerError::unavailable())?;
    receiver
        .recv()
        .await
        .unwrap_or_else(|| Err(NativeExportPickerError::unavailable()))
}
