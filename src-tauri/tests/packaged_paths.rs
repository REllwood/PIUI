use piui_lib::supervisor::SupervisorPaths;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

fn temporary_bundle() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("piui-bundle-paths-{}-{nonce}", std::process::id()))
}

#[test]
fn bundle_shaped_paths_resolve_only_inside_contents() {
    let root = temporary_bundle();
    let executable_dir = root.join("PIUI.app/Contents/MacOS");
    let resource_dir = root.join("PIUI.app/Contents/Resources");
    let sidecar = resource_dir.join("resources/sidecar");
    fs::create_dir_all(sidecar.join("dist")).unwrap();
    fs::create_dir_all(&executable_dir).unwrap();
    let node = executable_dir.join("piui-node");
    fs::write(&node, b"#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(sidecar.join("dist/index.js"), b"process.exit(0);\n").unwrap();
    fs::write(sidecar.join("manifest.json"), b"{}\n").unwrap();

    let paths = SupervisorPaths::from_bundle_layout(&executable_dir, &resource_dir)
        .expect("bundle paths resolve");
    assert_eq!(paths.node, fs::canonicalize(&node).unwrap());
    assert_eq!(paths.resource_root, fs::canonicalize(&sidecar).unwrap());
    assert!(paths.entrypoint.starts_with(&paths.resource_root));

    let outside = root.join("outside-node");
    fs::write(&outside, b"#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_file(&node).unwrap();
        symlink(&outside, &node).unwrap();
        assert!(SupervisorPaths::from_bundle_layout(&executable_dir, &resource_dir).is_err());
    }

    fs::remove_dir_all(root).unwrap();
}
