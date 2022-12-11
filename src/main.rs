use std::process::exit;

use clap::Parser;

mod cli;
mod safe;

use cli::{Args, Commands};
use safe::Safe;

fn prompt_password() -> String {
    rpassword::prompt_password("Enter safe key: ").unwrap()
}

fn main() {
    let args: Args = Args::parse();
    let mut safe = Safe::new(args.safe);
    if let Err(e) = safe.load(prompt_password) {
        eprintln!("!! ERROR : {}", e);
        exit(-1);
    }
    match args.command {
        Commands::List => safe.list(None, false),
        Commands::Find { regex, show_pw } => safe.list(Some(regex), show_pw),
    }
}
