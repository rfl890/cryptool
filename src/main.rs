mod subcommands;
mod util;

use clap::{Parser, Subcommand};

static LONG_ABOUT: &str = "A tool to run different types of cryptographic algorithms.";

#[derive(Parser)]
#[command(version, about, long_about = LONG_ABOUT)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Hashes files with the chosen algorithm, default is SHA-256
    Hash(subcommands::hash::HashArgs),
}

fn main() {
    let cli = Cli::parse_from(wild::args_os());
    match &cli.command {
        Commands::Hash(enc_args) => {
            subcommands::hash::handle_hash(enc_args, cli.verbose);
        }
    }
}
