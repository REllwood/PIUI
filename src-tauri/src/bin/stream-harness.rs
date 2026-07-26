#[cfg(debug_assertions)]
fn main() {
    use piui_lib::commands::bridge::{BridgeState, bridge_send_transport, bridge_stop_transport};
    use piui_lib::commands::harness_output::HarnessOutputQueue;
    use piui_lib::commands::stream::{cancel_stream_transport, run_stream_transport};
    use piui_lib::protocol::{Envelope, ProtocolKind};
    use piui_lib::supervisor::SupervisorPaths;
    use std::io::BufRead;
    use std::sync::Arc;

    let paths = match (
        std::env::var_os("PIUI_HARNESS_TEST_NODE"),
        std::env::var_os("PIUI_HARNESS_TEST_RESOURCES"),
    ) {
        (Some(node), Some(resources)) => SupervisorPaths::validated(node.into(), resources.into())
            .expect("isolated harness test paths"),
        _ => SupervisorPaths::development().expect("development sidecar paths"),
    };
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
                    let output = HarnessOutputQueue::stdout()?;
                    let result = run_stream_transport(&stream_state, envelope, |event| {
                        output.enqueue(event)
                    });
                    let close = output.close();
                    result.and(close)
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
