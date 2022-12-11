use std::path::PathBuf;

use clap::{Parser, Subcommand};
use regex::{Regex, RegexBuilder};

#[derive(Parser)]
pub struct Args {
    /// Path to the Revelation safe.
    #[arg(short, long, default_value = "~/revelation.safe")]
    pub safe: PathBuf,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List entries
    List,
    /// List entries with name matching a regex
    Find {
        /// The needle
        #[arg(value_parser = ci_regex)]
        regex: Regex,
        /// Show password
        #[arg(long = "pw", default_value = "false")]
        show_pw: bool,
    },
}

fn ci_regex(s: &str) -> Result<Regex, String> {
    match RegexBuilder::new(s).case_insensitive(true).build() {
        Err(e) => Err(format!("{:?}", e)),
        Ok(re) => Ok(re),
    }
}
