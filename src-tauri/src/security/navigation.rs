use tauri::{Runtime, Url, plugin::TauriPlugin};

const DEVELOPMENT_HOST: &str = "127.0.0.1";
const DEVELOPMENT_PORT: u16 = 1420;

pub fn is_allowed_navigation(url: &Url, debug_build: bool) -> bool {
    let production_origin = url.scheme() == "tauri"
        && url.host_str() == Some("localhost")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if production_origin {
        return true;
    }

    debug_build
        && url.scheme() == "http"
        && url.host_str() == Some(DEVELOPMENT_HOST)
        && url.port() == Some(DEVELOPMENT_PORT)
        && url.username().is_empty()
        && url.password().is_none()
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("navigation-containment")
        .on_navigation(|_, url| is_allowed_navigation(url, cfg!(debug_assertions)))
        .build()
}

#[cfg(test)]
mod tests {
    use super::is_allowed_navigation;
    use tauri::Url;

    fn url(value: &str) -> Url {
        Url::parse(value).expect("test URL should parse")
    }

    #[test]
    fn release_allows_only_the_bundled_application_origin() {
        assert!(is_allowed_navigation(&url("tauri://localhost/"), false));
        assert!(is_allowed_navigation(
            &url("tauri://localhost/?spike=markdown"),
            false
        ));

        for blocked in [
            "tauri://other/",
            "https://example.invalid/",
            "http://127.0.0.1:1420/",
            "file:///synthetic/project/history.jsonl",
            "data:text/html,probe",
            "blob:https://example.invalid/00000000-0000-0000-0000-000000000000",
            "asset://localhost/synthetic.png",
            "ipc://localhost/bridge_send",
            "javascript:alert(1)",
            "piui-command://host_status",
        ] {
            assert!(
                !is_allowed_navigation(&url(blocked), false),
                "release unexpectedly allowed {blocked}"
            );
        }
    }

    #[test]
    fn debug_allows_only_the_exact_vite_origin_in_addition() {
        assert!(is_allowed_navigation(
            &url("http://127.0.0.1:1420/?spike=markdown"),
            true
        ));
        assert!(is_allowed_navigation(&url("tauri://localhost/"), true));

        for blocked in [
            "http://localhost:1420/",
            "http://127.0.0.1:1421/",
            "https://127.0.0.1:1420/",
            "http://127.0.0.2:1420/",
            "http://example.invalid:1420/",
        ] {
            assert!(
                !is_allowed_navigation(&url(blocked), true),
                "debug unexpectedly allowed {blocked}"
            );
        }
    }
}
