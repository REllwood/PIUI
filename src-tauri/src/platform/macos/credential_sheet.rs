use super::super::{
    CredentialSecretValidation, CredentialSheetDecision, NativeCredentialSheetError,
    credential_secret_validation,
};
use crate::credentials::SecretMaterial;
use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{NSObjectProtocol, ProtocolObject};
use objc2::{DefinedClass, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSAccessibility, NSAlert, NSAlertFirstButtonReturn, NSButton, NSControlStateValueOff,
    NSControlStateValueOn, NSControlTextEditingDelegate, NSModalResponse, NSPasteboard,
    NSPasteboardTypeString, NSSecureTextField, NSTextField, NSTextFieldDelegate, NSView, NSWindow,
    NSWindowWillCloseNotification,
};
use objc2_foundation::{
    MainThreadMarker, NSNotification, NSNotificationCenter, NSObject, NSPoint, NSRect, NSSize,
    NSString, NSUTF8StringEncoding,
};
use std::cell::{Cell, RefCell};
use tauri::WebviewWindow;

const ACCESSORY_WIDTH: f64 = 420.0;
const ACCESSORY_HEIGHT: f64 = 150.0;
const FIELD_HEIGHT: f64 = 28.0;
const BUTTON_HEIGHT: f64 = 44.0;

type CredentialSheetOutcome = Result<CredentialSheetDecision, NativeCredentialSheetError>;
type CompletionSender = tauri::async_runtime::Sender<CredentialSheetOutcome>;

struct CredentialSheetControllerIvars {
    secure_field: Retained<NSSecureTextField>,
    reveal_field: Retained<NSTextField>,
    paste_button: Retained<NSButton>,
    reveal_button: Retained<NSButton>,
    validation_label: Retained<NSTextField>,
    save_button: Retained<NSButton>,
    revealing: Cell<bool>,
    completion_sender: RefCell<Option<CompletionSender>>,
    completed: Cell<bool>,
    observing_parent_close: Cell<bool>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements. The controller and
    // all retained controls are created and used only on AppKit's main thread.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = CredentialSheetControllerIvars]
    struct CredentialSheetController;

    // SAFETY: NSObjectProtocol has no additional implementation requirements.
    unsafe impl NSObjectProtocol for CredentialSheetController {}

    // SAFETY: This method has the selector and argument signature declared by
    // NSControlTextEditingDelegate and is main-thread confined by the class.
    unsafe impl NSControlTextEditingDelegate for CredentialSheetController {
        #[unsafe(method(controlTextDidChange:))]
        fn control_text_did_change(&self, _notification: &NSNotification) {
            self.update_validation();
        }
    }

    // SAFETY: NSTextFieldDelegate adds only optional methods; its required
    // super-protocol implementation is provided above.
    unsafe impl NSTextFieldDelegate for CredentialSheetController {}

    impl CredentialSheetController {
        // SAFETY: The selector is installed only on the native Paste button.
        #[unsafe(method(pasteAPIKey:))]
        fn paste_api_key(&self, _sender: &NSButton) {
            let pasteboard = NSPasteboard::generalPasteboard();
            let Some(value) = pasteboard.stringForType(unsafe { NSPasteboardTypeString }) else {
                self.clear_active_field();
                self.update_validation();
                return;
            };

            let validation = validation_for_value(&value);
            if validation != CredentialSecretValidation::Ready {
                self.clear_active_field();
                self.ivars().save_button.setEnabled(false);
                let message = match validation {
                    CredentialSecretValidation::Empty => "Enter an API key to continue.",
                    CredentialSecretValidation::TooLong => "The API key is too long.",
                    CredentialSecretValidation::Ready => unreachable!(),
                };
                self.ivars()
                    .validation_label
                    .setStringValue(&NSString::from_str(message));
                return;
            }

            if self.ivars().revealing.get() {
                self.ivars().reveal_field.setStringValue(&value);
            } else {
                self.ivars().secure_field.setStringValue(&value);
            }
            self.update_validation();
        }

        // SAFETY: The selector is installed only on the native Show/Hide
        // checkbox, which is retained by this controller.
        #[unsafe(method(toggleAPIKeyVisibility:))]
        fn toggle_api_key_visibility(&self, _sender: &NSButton) {
            let revealing = !self.ivars().revealing.get();
            if revealing {
                let value = self.ivars().secure_field.stringValue();
                self.ivars().reveal_field.setStringValue(&value);
                self.ivars()
                    .secure_field
                    .setStringValue(&NSString::new());
                self.ivars().secure_field.setHidden(true);
                self.ivars().reveal_field.setHidden(false);
                self.ivars()
                    .reveal_button
                    .setTitle(&NSString::from_str("Hide API key"));
                self.ivars().reveal_button.setState(NSControlStateValueOn);
                if let Some(window) = self.ivars().reveal_field.window() {
                    window.makeFirstResponder(Some(&self.ivars().reveal_field));
                }
            } else {
                let value = self.ivars().reveal_field.stringValue();
                self.ivars().secure_field.setStringValue(&value);
                self.ivars()
                    .reveal_field
                    .setStringValue(&NSString::new());
                self.clear_reveal_editor_undo();
                self.ivars().reveal_field.setHidden(true);
                self.ivars().secure_field.setHidden(false);
                self.ivars()
                    .reveal_button
                    .setTitle(&NSString::from_str("Show API key"));
                self.ivars().reveal_button.setState(NSControlStateValueOff);
                if let Some(window) = self.ivars().secure_field.window() {
                    window.makeFirstResponder(Some(&self.ivars().secure_field));
                }
            }
            self.ivars().revealing.set(revealing);
            self.update_key_view_loop();
            self.update_validation();
        }

        // SAFETY: The controller is registered for this selector only with
        // NSWindowWillCloseNotification from its calling parent window.
        #[unsafe(method(parentWindowWillClose:))]
        fn parent_window_will_close(&self, _notification: &NSNotification) {
            self.settle(Err(NativeCredentialSheetError::unavailable()));
        }
    }
);

impl CredentialSheetController {
    fn new(
        mtm: MainThreadMarker,
        save_button: Retained<NSButton>,
        cancel_button: &NSButton,
        completion_sender: CompletionSender,
    ) -> (Retained<Self>, Retained<NSView>) {
        let field_frame = NSRect::new(
            NSPoint::new(0.0, 82.0),
            NSSize::new(ACCESSORY_WIDTH, FIELD_HEIGHT),
        );
        let secure_field =
            NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), field_frame);
        let reveal_field = NSTextField::initWithFrame(NSTextField::alloc(mtm), field_frame);
        reveal_field.setHidden(true);
        reveal_field.setAutomaticTextCompletionEnabled(false);
        reveal_field.setAllowsEditingTextAttributes(false);
        reveal_field.setImportsGraphics(false);

        secure_field.setAccessibilityProtectedContent(true);
        reveal_field.setAccessibilityProtectedContent(true);
        secure_field.setAccessibilityLabel(Some(&NSString::from_str("API key")));
        reveal_field.setAccessibilityLabel(Some(&NSString::from_str("API key")));

        let label = NSTextField::labelWithString(&NSString::from_str("API key"), mtm);
        label.setFrame(NSRect::new(
            NSPoint::new(0.0, 116.0),
            NSSize::new(ACCESSORY_WIDTH, 20.0),
        ));
        // SAFETY: The label and both fields are retained by the same accessory
        // view/controller lifetime.
        unsafe {
            secure_field.setAccessibilityTitleUIElement(Some(&*label));
            reveal_field.setAccessibilityTitleUIElement(Some(&*label));
        }

        let validation_label =
            NSTextField::labelWithString(&NSString::from_str("Enter an API key to continue."), mtm);
        validation_label.setFrame(NSRect::new(
            NSPoint::new(0.0, 58.0),
            NSSize::new(ACCESSORY_WIDTH, 18.0),
        ));

        // SAFETY: Targets and selectors are installed after the controller is
        // initialised and retained for the lifetime of both buttons.
        let paste_button = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str("Paste API key"),
                None,
                None,
                mtm,
            )
        };
        paste_button.setFrame(NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(150.0, BUTTON_HEIGHT),
        ));
        paste_button.setAccessibilityHelp(Some(&NSString::from_str(
            "Pastes text from the clipboard into the protected API key field.",
        )));

        // A standard checkbox exposes the Show/Hide state to accessibility.
        let reveal_button = unsafe {
            NSButton::checkboxWithTitle_target_action(
                &NSString::from_str("Show API key"),
                None,
                None,
                mtm,
            )
        };
        reveal_button.setFrame(NSRect::new(
            NSPoint::new(166.0, 0.0),
            NSSize::new(180.0, BUTTON_HEIGHT),
        ));
        reveal_button.setAccessibilityHelp(Some(&NSString::from_str(
            "Shows or hides the API key inside this protected macOS sheet.",
        )));

        let accessory = NSView::initWithFrame(
            NSView::alloc(mtm),
            NSRect::new(
                NSPoint::new(0.0, 0.0),
                NSSize::new(ACCESSORY_WIDTH, ACCESSORY_HEIGHT),
            ),
        );
        accessory.addSubview(&label);
        accessory.addSubview(&secure_field);
        accessory.addSubview(&reveal_field);
        accessory.addSubview(&validation_label);
        accessory.addSubview(&paste_button);
        accessory.addSubview(&reveal_button);

        save_button.setEnabled(false);
        let this = Self::alloc(mtm).set_ivars(CredentialSheetControllerIvars {
            secure_field,
            reveal_field,
            paste_button,
            reveal_button,
            validation_label,
            save_button,
            revealing: Cell::new(false),
            completion_sender: RefCell::new(Some(completion_sender)),
            completed: Cell::new(false),
            observing_parent_close: Cell::new(false),
        });
        // SAFETY: NSObject's init signature is correct for this subclass.
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };

        // SAFETY: The controller implements each installed selector and both
        // text fields' delegate protocols, and the controller is retained by
        // the escaping sheet completion block.
        unsafe {
            this.ivars().paste_button.setTarget(Some(&*this));
            this.ivars()
                .paste_button
                .setAction(Some(sel!(pasteAPIKey:)));
            this.ivars().reveal_button.setTarget(Some(&*this));
            this.ivars()
                .reveal_button
                .setAction(Some(sel!(toggleAPIKeyVisibility:)));
            let delegate: &ProtocolObject<dyn NSTextFieldDelegate> =
                ProtocolObject::from_ref(&*this);
            this.ivars().secure_field.setDelegate(Some(delegate));
            this.ivars().reveal_field.setDelegate(Some(delegate));

            this.ivars()
                .secure_field
                .setNextKeyView(Some(&this.ivars().paste_button));
            this.ivars()
                .reveal_field
                .setNextKeyView(Some(&this.ivars().paste_button));
            this.ivars()
                .paste_button
                .setNextKeyView(Some(&this.ivars().reveal_button));
            this.ivars()
                .reveal_button
                .setNextKeyView(Some(cancel_button));
            cancel_button.setNextKeyView(Some(&this.ivars().save_button));
            this.ivars()
                .save_button
                .setNextKeyView(Some(&this.ivars().secure_field));
        }

        (this, accessory)
    }

    fn update_key_view_loop(&self) {
        let active_field = if self.ivars().revealing.get() {
            &*self.ivars().reveal_field
        } else {
            &*self.ivars().secure_field
        };
        // SAFETY: The active field and Save button are retained by this
        // controller and belong to the same native sheet.
        unsafe {
            self.ivars().save_button.setNextKeyView(Some(active_field));
        }
    }

    fn update_validation(&self) {
        let value = if self.ivars().revealing.get() {
            self.ivars().reveal_field.stringValue()
        } else {
            self.ivars().secure_field.stringValue()
        };
        let validation = validation_for_value(&value);
        if validation == CredentialSecretValidation::TooLong {
            self.clear_active_field();
            self.ivars().save_button.setEnabled(false);
            self.ivars()
                .validation_label
                .setStringValue(&NSString::from_str("The API key is too long."));
            return;
        }

        let valid = validation == CredentialSecretValidation::Ready;
        self.ivars().save_button.setEnabled(valid);
        let message = if validation == CredentialSecretValidation::Empty {
            "Enter an API key to continue."
        } else {
            "Ready to save in Keychain."
        };
        self.ivars()
            .validation_label
            .setStringValue(&NSString::from_str(message));
    }

    fn clear_active_field(&self) {
        if self.ivars().revealing.get() {
            self.ivars().reveal_field.setStringValue(&NSString::new());
            self.clear_reveal_editor_undo();
        } else {
            self.ivars().secure_field.setStringValue(&NSString::new());
        }
    }

    fn observe_parent_close(&self, parent: &NSWindow) {
        let notification_center = NSNotificationCenter::defaultCenter();
        // SAFETY: The selector is implemented by this controller, the
        // observed object is the retained calling window, and delivery is on
        // the same AppKit main thread where the observer is registered.
        unsafe {
            notification_center.addObserver_selector_name_object(
                self,
                sel!(parentWindowWillClose:),
                Some(NSWindowWillCloseNotification),
                Some(parent),
            );
        }
        self.ivars().observing_parent_close.set(true);
    }

    fn complete_with_response(&self, response: NSModalResponse) -> bool {
        if self.ivars().completed.get() {
            return false;
        }

        if let Some(window) = self.ivars().secure_field.window() {
            // SAFETY: Both fields belong to this sheet window and all editing
            // is ended synchronously on AppKit's main thread.
            unsafe { window.endEditingFor(None) };
        }

        let outcome = if response == NSAlertFirstButtonReturn {
            let value = if self.ivars().revealing.get() {
                self.ivars().reveal_field.stringValue()
            } else {
                self.ivars().secure_field.stringValue()
            };
            if validation_for_value(&value) != CredentialSecretValidation::Ready {
                Err(NativeCredentialSheetError::invalid_input())
            } else {
                SecretMaterial::new(value.to_string().into_bytes())
                    .map(CredentialSheetDecision::Save)
                    .map_err(|_| NativeCredentialSheetError::invalid_input())
            }
        } else {
            Ok(CredentialSheetDecision::Cancel)
        };

        self.settle(outcome)
    }

    fn settle(&self, outcome: CredentialSheetOutcome) -> bool {
        if self.ivars().completed.replace(true) {
            return false;
        }

        self.clear_fields();
        self.remove_parent_close_observer();
        if let Some(sender) = self.ivars().completion_sender.borrow_mut().take() {
            let _ = sender.try_send(outcome);
        }
        true
    }

    fn remove_parent_close_observer(&self) {
        if self.ivars().observing_parent_close.replace(false) {
            let notification_center = NSNotificationCenter::defaultCenter();
            // SAFETY: This removes the selector observer registered by
            // observe_parent_close before the controller can be released.
            unsafe { notification_center.removeObserver(self) };
        }
    }

    fn clear_reveal_editor_undo(&self) {
        if let Some(editor) = self.ivars().reveal_field.currentEditor()
            && let Some(undo_manager) = editor.undoManager()
        {
            undo_manager.removeAllActions();
        }
        if let Some(undo_manager) = self.ivars().reveal_field.undoManager() {
            undo_manager.removeAllActions();
        }
    }

    fn clear_fields(&self) {
        self.clear_reveal_editor_undo();
        if let Some(editor) = self.ivars().secure_field.currentEditor()
            && let Some(undo_manager) = editor.undoManager()
        {
            undo_manager.removeAllActions();
        }
        let _ = self.ivars().secure_field.abortEditing();
        let _ = self.ivars().reveal_field.abortEditing();
        self.ivars().secure_field.setStringValue(&NSString::new());
        self.ivars().reveal_field.setStringValue(&NSString::new());
        self.ivars().reveal_field.setHidden(true);
        self.ivars().secure_field.setHidden(false);
        self.ivars().reveal_button.setState(NSControlStateValueOff);
        self.ivars()
            .reveal_button
            .setTitle(&NSString::from_str("Show API key"));
        self.ivars().revealing.set(false);
    }
}

fn validation_for_value(value: &NSString) -> CredentialSecretValidation {
    credential_secret_validation(value.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
}

#[cfg(test)]
mod tests {
    use super::{CredentialSecretValidation, NSString, SecretMaterial, validation_for_value};

    #[test]
    fn nsstring_validation_uses_utf8_byte_boundaries() {
        let exact = "é".repeat(SecretMaterial::MAX_BYTES / "é".len());
        let over_limit = format!("{exact}é");

        assert_eq!(
            validation_for_value(&NSString::new()),
            CredentialSecretValidation::Empty
        );
        assert_eq!(
            validation_for_value(&NSString::from_str(&exact)),
            CredentialSecretValidation::Ready
        );
        assert_eq!(
            validation_for_value(&NSString::from_str(&over_limit)),
            CredentialSecretValidation::TooLong
        );
    }
}

pub(crate) async fn present(
    window: WebviewWindow,
    provider_label: String,
) -> Result<CredentialSheetDecision, NativeCredentialSheetError> {
    let (sender, mut receiver) = tauri::async_runtime::channel(1);
    window
        .with_webview(move |webview| {
            let Some(mtm) = MainThreadMarker::new() else {
                let _ = sender.try_send(Err(NativeCredentialSheetError::unavailable()));
                return;
            };
            // SAFETY: Tauri documents that with_webview runs on the main
            // thread and that ns_window is its valid calling NSWindow. It is
            // retained here before the raw platform pointer leaves this scope.
            let Some(parent) =
                (unsafe { Retained::<NSWindow>::retain(webview.ns_window().cast()) })
            else {
                let _ = sender.try_send(Err(NativeCredentialSheetError::unavailable()));
                return;
            };

            let alert = NSAlert::new(mtm);
            alert.setMessageText(&NSString::from_str(&format!(
                "Add an API key for {provider_label}"
            )));
            alert.setInformativeText(&NSString::from_str(
                "The API key stays in this macOS sheet and is saved in Keychain.",
            ));
            let save_button = alert.addButtonWithTitle(&NSString::from_str("Save"));
            let cancel_button = alert.addButtonWithTitle(&NSString::from_str("Cancel"));
            let (controller, accessory) =
                CredentialSheetController::new(mtm, save_button, &cancel_button, sender);
            alert.setAccessoryView(Some(&accessory));
            alert.layout();
            let sheet_window = alert.window();
            sheet_window.setInitialFirstResponder(Some(&controller.ivars().secure_field));

            controller.observe_parent_close(&parent);
            let completion_parent = parent.clone();
            let completion_controller = controller.clone();
            let completion: RcBlock<dyn Fn(NSModalResponse) + 'static> =
                RcBlock::new(move |response| {
                    if completion_controller.complete_with_response(response) {
                        completion_parent.makeKeyAndOrderFront(None);
                    }
                });
            alert.beginSheetModalForWindow_completionHandler(&parent, Some(&completion));
            sheet_window.makeFirstResponder(Some(&controller.ivars().secure_field));
        })
        .map_err(|_| NativeCredentialSheetError::unavailable())?;

    receiver
        .recv()
        .await
        .unwrap_or_else(|| Err(NativeCredentialSheetError::unavailable()))
}
