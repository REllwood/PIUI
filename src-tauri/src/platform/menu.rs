#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MenuRoute {
    pub id: &'static str,
    pub accelerator: &'static str,
}

pub const MENU_ROUTES: [MenuRoute; 9] = [
    MenuRoute {
        id: "new-conversation",
        accelerator: "CmdOrCtrl+N",
    },
    MenuRoute {
        id: "open-command-menu",
        accelerator: "CmdOrCtrl+K",
    },
    MenuRoute {
        id: "choose-project",
        accelerator: "CmdOrCtrl+Shift+O",
    },
    MenuRoute {
        id: "open-sessions",
        accelerator: "CmdOrCtrl+Shift+S",
    },
    MenuRoute {
        id: "toggle-navigation",
        accelerator: "CmdOrCtrl+Alt+S",
    },
    MenuRoute {
        id: "open-settings",
        accelerator: "CmdOrCtrl+,",
    },
    MenuRoute {
        id: "stop-turn",
        accelerator: "CmdOrCtrl+.",
    },
    MenuRoute {
        id: "alternate-send",
        accelerator: "CmdOrCtrl+Enter",
    },
    MenuRoute {
        id: "close-window",
        accelerator: "CmdOrCtrl+W",
    },
];

/// Standard text-editing commands. WKWebView only receives Cmd-Z/X/C/V/A
/// through the native responder chain, so they must exist as predefined menu
/// items; without an Edit menu those shortcuts silently do nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditCommand {
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
    SelectAll,
}

impl EditCommand {
    /// The shortcut macOS binds to the predefined item.
    pub const fn accelerator(self) -> &'static str {
        match self {
            Self::Undo => "CmdOrCtrl+Z",
            Self::Redo => "CmdOrCtrl+Shift+Z",
            Self::Cut => "CmdOrCtrl+X",
            Self::Copy => "CmdOrCtrl+C",
            Self::Paste => "CmdOrCtrl+V",
            Self::SelectAll => "CmdOrCtrl+A",
        }
    }
}

pub const EDIT_COMMANDS: [EditCommand; 6] = [
    EditCommand::Undo,
    EditCommand::Redo,
    EditCommand::Cut,
    EditCommand::Copy,
    EditCommand::Paste,
    EditCommand::SelectAll,
];

pub struct MenuState {
    new_conversation: tauri::menu::MenuItem<tauri::Wry>,
    choose_project: tauri::menu::MenuItem<tauri::Wry>,
    stop_turn: tauri::menu::MenuItem<tauri::Wry>,
    alternate_send: tauri::menu::MenuItem<tauri::Wry>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MenuEnabledState {
    can_create: bool,
    can_choose_project: bool,
    can_stop: bool,
    can_send: bool,
}

#[tauri::command]
pub fn menu_set_enabled_state(
    state: tauri::State<'_, MenuState>,
    menu_state: MenuEnabledState,
) -> Result<(), String> {
    state
        .new_conversation
        .set_enabled(menu_state.can_create)
        .and_then(|_| {
            state
                .choose_project
                .set_enabled(menu_state.can_choose_project)
        })
        .and_then(|_| state.stop_turn.set_enabled(menu_state.can_stop))
        .and_then(|_| state.alternate_send.set_enabled(menu_state.can_send))
        .map_err(|_| "menu-state-update-failed".into())
}

pub fn menu_routes_are_unique() -> bool {
    MENU_ROUTES.iter().enumerate().all(|(index, route)| {
        MENU_ROUTES[index + 1..]
            .iter()
            .all(|candidate| candidate.id != route.id && candidate.accelerator != route.accelerator)
    }) && EDIT_COMMANDS.iter().all(|command| {
        MENU_ROUTES
            .iter()
            .all(|route| route.accelerator != command.accelerator())
    })
}

pub fn install(app: &tauri::App) -> tauri::Result<()> {
    use tauri::Manager;
    use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};

    if !menu_routes_are_unique() {
        return Err(tauri::Error::AssetNotFound(
            "native menu routes are not unique".into(),
        ));
    }
    let item = |id: &'static str, label: &'static str, accelerator: &'static str| {
        MenuItemBuilder::with_id(id, label)
            .accelerator(accelerator)
            .build(app)
    };
    let new_conversation = item("new-conversation", "New Conversation", "CmdOrCtrl+N")?;
    let command_menu = item("open-command-menu", "Command Menu…", "CmdOrCtrl+K")?;
    let choose_project = item("choose-project", "Choose Project…", "CmdOrCtrl+Shift+O")?;
    let sessions = item("open-sessions", "Sessions", "CmdOrCtrl+Shift+S")?;
    let navigation = item("toggle-navigation", "Toggle Navigation", "CmdOrCtrl+Alt+S")?;
    let settings = item("open-settings", "Settings…", "CmdOrCtrl+,")?;
    let stop = item("stop-turn", "Stop Current Turn", "CmdOrCtrl+.")?;
    let alternate_send = item("alternate-send", "Send Message", "CmdOrCtrl+Enter")?;
    new_conversation.set_enabled(false)?;
    stop.set_enabled(false)?;
    alternate_send.set_enabled(false)?;

    let application = SubmenuBuilder::new(app, "PIUI")
        .about(None)
        .separator()
        .item(&settings)
        .separator()
        .services()
        .separator()
        .quit()
        .build()?;
    let file = SubmenuBuilder::new(app, "File")
        .item(&new_conversation)
        .item(&choose_project)
        .item(&sessions)
        .separator()
        .close_window()
        .build()?;
    let conversation = SubmenuBuilder::new(app, "Conversation")
        .item(&command_menu)
        .item(&alternate_send)
        .item(&stop)
        .build()?;
    let mut edit = SubmenuBuilder::new(app, "Edit");
    for command in EDIT_COMMANDS {
        edit = match command {
            EditCommand::Undo => edit.undo(),
            EditCommand::Redo => edit.redo().separator(),
            EditCommand::Cut => edit.cut(),
            EditCommand::Copy => edit.copy(),
            EditCommand::Paste => edit.paste(),
            EditCommand::SelectAll => edit.select_all(),
        };
    }
    let edit = edit.build()?;
    let view = SubmenuBuilder::new(app, "View").item(&navigation).build()?;
    let menu = MenuBuilder::new(app)
        .items(&[&application, &file, &edit, &conversation, &view])
        .build()?;
    app.set_menu(menu)?;
    app.manage(MenuState {
        new_conversation,
        choose_project,
        stop_turn: stop,
        alternate_send,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_menu_provides_every_standard_text_command_without_route_collisions() {
        for required in [
            EditCommand::Undo,
            EditCommand::Redo,
            EditCommand::Cut,
            EditCommand::Copy,
            EditCommand::Paste,
            EditCommand::SelectAll,
        ] {
            assert!(EDIT_COMMANDS.contains(&required), "{required:?} missing");
        }
        assert!(menu_routes_are_unique());
        for command in EDIT_COMMANDS {
            assert!(
                MENU_ROUTES
                    .iter()
                    .all(|route| route.accelerator != command.accelerator()),
                "{command:?} shortcut is taken by an application route"
            );
        }
    }
}
