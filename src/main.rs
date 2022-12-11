use std::process::exit;

use clap::Parser;

mod cli;
mod safe;

use cli::Args;
use safe::Safe;

fn prompt_password() -> String {
    rpassword::prompt_password("Safe key: ").unwrap()
}

fn main() {
    let args: Args = Args::parse();
    let mut safe = Safe::new(args.safe);
    if let Err(e) = safe.load(prompt_password) {
        eprintln!("!! ERROR : {}", e);
        exit(-1);
    }
    println!("All ok");
}
