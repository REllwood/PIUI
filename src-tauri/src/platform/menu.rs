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
    let view = SubmenuBuilder::new(app, "View").item(&navigation).build()?;
    let menu = MenuBuilder::new(app)
        .items(&[&application, &file, &conversation, &view])
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
