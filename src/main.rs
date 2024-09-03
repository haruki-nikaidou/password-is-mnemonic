mod repeater;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    password: String,
}

fn main() {
    let args = Args::parse();
    if args.password.len() < 32 {
        eprintln!("Password must be at least 32 characters long");
        std::process::exit(1);
    }
    let repeated = repeater::get_repeated(args.password, 32);
    let hashed = repeater::get_hashed(repeated, 32);
    let mnemonic = bip39::Mnemonic::from_entropy(&hashed).unwrap();
    let mnemonic = repeater::mnemonic_to_string(&mnemonic);
    println!("{}", mnemonic);
}
