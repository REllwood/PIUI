use super::super::NativeAttachmentPickerError;
use block2::RcBlock;
use objc2::rc::Retained;
use objc2_app_kit::{NSModalResponse, NSModalResponseOK, NSOpenPanel, NSWindow};
use objc2_foundation::{MainThreadMarker, NSArray, NSString};
use std::path::PathBuf;
use tauri::WebviewWindow;

pub(crate) async fn present(
    window: WebviewWindow,
) -> Result<Option<PathBuf>, NativeAttachmentPickerError> {
    let (sender, mut receiver) = tauri::async_runtime::channel(1);
    window
        .with_webview(move |webview| {
            let Some(mtm) = MainThreadMarker::new() else {
                let _ = sender.try_send(Err(NativeAttachmentPickerError::unavailable()));
                return;
            };
            // SAFETY: Tauri invokes this callback on AppKit's main thread. The
            // retained NSWindow remains valid for the lifetime of the sheet.
            let Some(parent) =
                (unsafe { Retained::<NSWindow>::retain(webview.ns_window().cast()) })
            else {
                let _ = sender.try_send(Err(NativeAttachmentPickerError::unavailable()));
                return;
            };
            let panel = NSOpenPanel::openPanel(mtm);
            panel.setCanChooseDirectories(false);
            panel.setCanChooseFiles(true);
            panel.setAllowsMultipleSelection(false);
            panel.setResolvesAliases(false);
            panel.setCanCreateDirectories(false);
            let extensions = [
                NSString::from_str("png"),
                NSString::from_str("jpg"),
                NSString::from_str("jpeg"),
                NSString::from_str("webp"),
            ];
            let allowed = NSArray::from_retained_slice(&extensions);
            #[allow(deprecated)]
            panel.setAllowedFileTypes(Some(&allowed));
            let completion_panel = panel.clone();
            let completion: RcBlock<dyn Fn(NSModalResponse) + 'static> =
                RcBlock::new(move |response| {
                    let result = if response == NSModalResponseOK {
                        completion_panel
                            .URL()
                            .and_then(|url| url.path())
                            .map(|path| PathBuf::from(path.to_string()))
                            .ok_or_else(NativeAttachmentPickerError::unavailable)
                            .map(Some)
                    } else {
                        Ok(None)
                    };
                    let _ = sender.try_send(result);
                });
            panel.beginSheetModalForWindow_completionHandler(&parent, &completion);
        })
        .map_err(|_| NativeAttachmentPickerError::unavailable())?;
    receiver
        .recv()
        .await
        .unwrap_or_else(|| Err(NativeAttachmentPickerError::unavailable()))
}
