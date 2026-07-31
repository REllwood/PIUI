use piui_lib::commands::project_trust_harness::run_packaged_project_trust_harness;
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};

const FAILURE: &str = "A.24 project trust harness rejected.\n";

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let accepted = matches!(catch_unwind(AssertUnwindSafe(run)), Ok(Ok(())));
    if !accepted {
        fail();
    }
}

fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let evidence = run_packaged_project_trust_harness().map_err(|_| ())?;
    let mut encoded = serde_json::to_vec(&evidence).map_err(|_| ())?;
    encoded.push(b'\n');
    std::io::stdout().lock().write_all(&encoded).map_err(|_| ())
}

fn fail() {
    let _ = std::io::stderr().lock().write_all(FAILURE.as_bytes());
    std::process::exit(1);
}
