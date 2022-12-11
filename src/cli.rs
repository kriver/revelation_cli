use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to the Revelation safe.
    /// // FIXME tilde
    #[arg(short, long, default_value = "~/revelation.safe")]
    pub safe: PathBuf,
}
