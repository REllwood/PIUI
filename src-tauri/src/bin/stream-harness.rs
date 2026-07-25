#[cfg(debug_assertions)]
fn main() {
    use piui_lib::commands::stream::run_stream;
    use piui_lib::protocol::{Envelope, ProtocolKind};
    use piui_lib::supervisor::{SidecarSupervisor, SupervisorPaths};
    use std::io::{BufRead, Write};
    use std::sync::{Arc, Mutex};

    let paths = SupervisorPaths::development().expect("development sidecar paths");
    let supervisor = Arc::new(Mutex::new(SidecarSupervisor::default()));
    let mut stream_thread = None;

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(envelope) = serde_json::from_str::<Envelope>(&line) else {
            eprintln!("invalid harness input");
            continue;
        };
        match envelope.kind {
            ProtocolKind::Request if stream_thread.is_none() => {
                let stream_supervisor = Arc::clone(&supervisor);
                let stream_paths = paths.clone();
                stream_thread = Some(std::thread::spawn(move || {
                    run_stream(stream_supervisor, stream_paths, envelope, |event| {
                        let encoded = serde_json::to_string(event)
                            .map_err(|_| "harness event encoding failed".to_string())?;
                        let mut stdout = std::io::stdout().lock();
                        writeln!(stdout, "{encoded}")
                            .and_then(|_| stdout.flush())
                            .map_err(|_| "harness output failed".to_string())
                    })
                }));
            }
            ProtocolKind::Request => {
                if let Ok(mut supervisor) = supervisor.lock()
                    && let Err(error) = supervisor.send_envelope(&envelope)
                {
                    eprintln!("{error}");
                }
            }
            ProtocolKind::Cancel => {
                if let Ok(mut supervisor) = supervisor.lock()
                    && let Err(error) = supervisor.send_envelope(&envelope)
                {
                    eprintln!("{error}");
                }
            }
            _ => eprintln!("unsupported harness input"),
        }
    }

    if let Some(thread) = stream_thread {
        match thread.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("{error}"),
            Err(_) => eprintln!("stream harness worker failed"),
        }
    }
    if let Ok(mut supervisor) = supervisor.lock() {
        let _ = supervisor.stop();
    }
}

#[cfg(not(debug_assertions))]
fn main() {
    eprintln!("The stream harness is available only in debug test builds.");
    std::process::exit(64);
}
