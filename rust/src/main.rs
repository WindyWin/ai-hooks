use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(cmd @ ("install" | "uninstall")) => {
            let mut opts = args[1..].to_vec();
            if cmd == "uninstall" {
                opts.push("--uninstall".into());
            }
            if let Err(e) = mask_secrets::install::run(&opts) {
                eprintln!("mask-secrets: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("--version" | "-V") => {
            println!("mask-secrets {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("--help" | "-h" | "help") => {
            print!("{}", mask_secrets::install::USAGE);
            return;
        }
        Some(other) => {
            // Agents run the hook with no arguments; anything else is a mistake, not a payload to wait for.
            eprintln!(
                "mask-secrets: unknown argument {other:?}\n\n{}",
                mask_secrets::install::USAGE
            );
            std::process::exit(2);
        }
        None => {}
    }

    // Hook mode. A panic must never print anything: the library already fails closed on its own.
    std::panic::set_hook(Box::new(|_| {}));
    let mut bytes = Vec::new();
    if std::io::stdin().read_to_end(&mut bytes).is_err() {
        return;
    }
    let raw = String::from_utf8_lossy(&bytes);
    if let Some(out) = mask_secrets::run(&raw) {
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(out.as_bytes());
        let _ = stdout.flush();
    }
}
