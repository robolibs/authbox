use authbox::{did, log_startup};

#[derive(Debug)]
struct Args {
    name: String,
    count: usize,
    files: Vec<String>,
    did_uri: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    log_startup();

    let args = parse_args()?;
    for _ in 0..args.count {
        println!("Hello, {}!", args.name);
    }

    if !args.files.is_empty() {
        println!("\nWould process files: {}", args.files.join(", "));
    }

    match did::parse(&args.did_uri) {
        Ok(parsed) => println!("Parsed DID method={}", parsed.method),
        Err(_) => eprintln!("Invalid DID: {}", args.did_uri),
    }

    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut name = None;
    let mut count = 1usize;
    let mut files = Vec::new();
    let mut did_uri = "did:web:example.com".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--count" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a NUM value"))?;
                count = value
                    .parse::<usize>()
                    .map_err(|_| format!("{arg} requires a positive integer"))?;
            }
            "-f" | "--file" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a FILE value"))?;
                files.push(value);
            }
            "--did" => {
                did_uri = args
                    .next()
                    .ok_or_else(|| "--did requires a DID value".to_string())?;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            value if value.starts_with('-') => {
                return Err(format!("Unknown flag: {value}").into());
            }
            value => {
                if name.is_some() {
                    return Err(format!("Unexpected extra positional argument: {value}").into());
                }
                name = Some(value.to_string());
            }
        }
    }

    Ok(Args {
        name: name.unwrap_or_else(|| "friend".to_string()),
        count,
        files,
        did_uri,
    })
}

fn print_usage() {
    println!("Usage: simple_example [NAME] [-c NUM] [-f FILE] [--did DID]");
}
