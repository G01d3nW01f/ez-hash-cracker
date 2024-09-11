use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use md5;
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

const SHA1_HEX_STRING_LENGTH: usize = 40;
const SHA256_HEX_STRING_LENGTH: usize = 64;
const MD5_HEX_STRING_LENGTH: usize = 32;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        println!("Usage: ");
        println!("ez-hash-cracker: <wordlist.txt> <hash_type> <hash_value>");
        println!("hash_type: sha1 | sha256 | md5");
        return Ok(());
    }

    let hash_type = args[2].trim();
    let hash_to_crack = args[3].trim();

    match hash_type {
        "sha1" if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH => {
            return Err("sha1 hash is not valid".into());
        }
        "sha256" if hash_to_crack.len() != SHA256_HEX_STRING_LENGTH => {
            return Err("sha256 hash is not valid".into());
        }
        "md5" if hash_to_crack.len() != MD5_HEX_STRING_LENGTH => {
            return Err("md5 hash is not valid".into());
        }
        _ if hash_type != "sha1" && hash_type != "sha256" && hash_type != "md5" => {
            return Err("Unsupported hash type".into());
        }
        _ => {}
    }

    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(&wordlist_file);

    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        let hash_result = match hash_type {
            "sha1" => {
                let mut hasher = Sha1::new();
                hasher.update(common_password.as_bytes());
                hex::encode(hasher.finalize())
            }
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(common_password.as_bytes());
                hex::encode(hasher.finalize())
            }
            "md5" => {
                let digest = md5::compute(common_password.as_bytes());
                hex::encode(digest.0)
            }
            _ => unreachable!(),
        };

        if hash_to_crack == hash_result {
            println!("Password found: {}", &common_password);
            return Ok(());
        }
    }

    println!("password not found in wordlist...");

    Ok(())
}

