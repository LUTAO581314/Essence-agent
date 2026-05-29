fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let code = match moxi_cli::run_with_io(std::env::args(), stdin.lock(), stdout.lock()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            2
        }
    };
    std::process::exit(code);
}
