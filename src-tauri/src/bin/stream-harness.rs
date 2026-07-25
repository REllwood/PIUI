#[cfg(debug_assertions)]
fn main() {
    use piui_lib::commands::bridge::{BridgeState, bridge_send_transport, bridge_stop_transport};
    use piui_lib::commands::stream::{cancel_stream_transport, run_stream_transport};
    use piui_lib::protocol::{Envelope, ProtocolKind};
    use piui_lib::supervisor::SupervisorPaths;
    use std::io::{BufRead, Write};
    use std::sync::Arc;

    let paths = SupervisorPaths::development().expect("development sidecar paths");
    let state = Arc::new(BridgeState::new(paths));
    let mut stream_thread = None;

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(envelope) = serde_json::from_str::<Envelope>(&line) else {
            eprintln!("invalid harness input");
            continue;
        };
        match envelope.kind {
            ProtocolKind::Request if stream_thread.is_none() => {
                let stream_state = Arc::clone(&state);
                stream_thread = Some(std::thread::spawn(move || {
                    run_stream_transport(&stream_state, envelope, |event| {
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
                if let Err(error) = bridge_send_transport(&state, &envelope) {
                    eprintln!("{error}");
                }
            }
            ProtocolKind::Cancel => {
                if let Err(error) = cancel_stream_transport(&state, envelope) {
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
    let _ = bridge_stop_transport(&state);
}

#[cfg(not(debug_assertions))]
fn main() {
    eprintln!("The stream harness is available only in debug test builds.");
    std::process::exit(64);
}
