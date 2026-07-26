use super::super::NativeFolderPickerError;
use block2::RcBlock;
use objc2::rc::Retained;
use objc2_app_kit::{NSModalResponse, NSModalResponseOK, NSOpenPanel, NSWindow};
use objc2_foundation::MainThreadMarker;
use std::path::PathBuf;
use tauri::WebviewWindow;

pub(crate) async fn present(
    window: WebviewWindow,
) -> Result<Option<PathBuf>, NativeFolderPickerError> {
    let (sender, mut receiver) = tauri::async_runtime::channel(1);
    window
        .with_webview(move |webview| {
            let Some(mtm) = MainThreadMarker::new() else {
                let _ = sender.try_send(Err(NativeFolderPickerError::unavailable()));
                return;
            };
            // SAFETY: Tauri runs this closure on AppKit's main thread and
            // exposes its live NSWindow. Retain it before leaving the callback.
            let Some(parent) =
                (unsafe { Retained::<NSWindow>::retain(webview.ns_window().cast()) })
            else {
                let _ = sender.try_send(Err(NativeFolderPickerError::unavailable()));
                return;
            };
            let panel = NSOpenPanel::openPanel(mtm);
            panel.setCanChooseDirectories(true);
            panel.setCanChooseFiles(false);
            panel.setAllowsMultipleSelection(false);
            panel.setResolvesAliases(false);
            panel.setCanCreateDirectories(false);
            let completion_panel = panel.clone();
            let completion: RcBlock<dyn Fn(NSModalResponse) + 'static> =
                RcBlock::new(move |response| {
                    let result = if response == NSModalResponseOK {
                        completion_panel
                            .URL()
                            .and_then(|url| url.path())
                            .map(|path| PathBuf::from(path.to_string()))
                            .ok_or_else(NativeFolderPickerError::unavailable)
                            .map(Some)
                    } else {
                        Ok(None)
                    };
                    let _ = sender.try_send(result);
                });
            panel.beginSheetModalForWindow_completionHandler(&parent, &completion);
        })
        .map_err(|_| NativeFolderPickerError::unavailable())?;
    receiver
        .recv()
        .await
        .unwrap_or_else(|| Err(NativeFolderPickerError::unavailable()))
}
