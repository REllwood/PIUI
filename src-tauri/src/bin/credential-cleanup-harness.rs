fn main() {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    if !piui_lib::a23_credential_maintenance::run_cleanup(&mut input, &mut output) {
        std::process::exit(1);
    }
}
