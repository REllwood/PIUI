use std::io::Write;

fn main() {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    if let Err(code) =
        piui_lib::a23_credential_maintenance::run_cleanup_with_failure_code(&mut input, &mut output)
    {
        let mut stderr = std::io::stderr().lock();
        if stderr.write_all(code.stderr_line()).is_err() || stderr.flush().is_err() {
            std::process::exit(1);
        }
        std::process::exit(1);
    }
}
