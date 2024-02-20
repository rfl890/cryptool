use clap::{Args, ValueEnum};
use crypto::digest::Digest;
use itertools::Itertools;
use md5::Md5;
use sha1::digest::DynDigest;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use crate::{unwrap_continue, vprintln};

static BUF_LENGTH: usize = 1048576;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum HashAlgorithm {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    BLAKE3,
}

#[derive(Args)]
pub struct HashArgs {
    #[arg(short, long, value_enum)]
    algorithm: Option<HashAlgorithm>,
    files: Vec<PathBuf>,
}

macro_rules! get_algorithm_string {
    ($algorithm:expr) => {
        match $algorithm {
            HashAlgorithm::MD5 => "MD5",
            HashAlgorithm::SHA1 => "SHA-1",
            HashAlgorithm::SHA224 => "SHA-224",
            HashAlgorithm::SHA256 => "SHA-256",
            HashAlgorithm::SHA384 => "SHA-384",
            HashAlgorithm::SHA512 => "SHA-512",
            HashAlgorithm::SHA512_224 => "SHA-512/224",
            HashAlgorithm::SHA512_256 => "SHA-512/256",
            HashAlgorithm::SHA3_224 => "SHA3-224",
            HashAlgorithm::SHA3_256 => "SHA3-256",
            HashAlgorithm::SHA3_384 => "SHA3-384",
            HashAlgorithm::SHA3_512 => "SHA3-512",
            HashAlgorithm::BLAKE3 => "BLAKE3",
        }
    };
}

macro_rules! get_algorithm_hasher {
    ($algorithm:expr) => {
        match $algorithm {
            HashAlgorithm::MD5 => Box::new(Md5::new()),
            HashAlgorithm::SHA1 => Box::new(Sha1::new()),
            HashAlgorithm::SHA224 => Box::new(Sha224::new()),
            HashAlgorithm::SHA256 => Box::new(Sha256::new()),
            HashAlgorithm::SHA384 => Box::new(Sha384::new()),
            HashAlgorithm::SHA512 => Box::new(Sha512::new()),
            HashAlgorithm::SHA512_224 => Box::new(Sha512_224::new()),
            HashAlgorithm::SHA512_256 => Box::new(Sha512_256::new()),
            HashAlgorithm::SHA3_224 => Box::new(Sha3_224::new()),
            HashAlgorithm::SHA3_256 => Box::new(Sha3_256::new()),
            HashAlgorithm::SHA3_384 => Box::new(Sha3_384::new()),
            HashAlgorithm::SHA3_512 => Box::new(Sha3_512::new()),
            HashAlgorithm::BLAKE3 => Box::new(blake3::Hasher::new()),
        }
    };
}

pub fn handle_hash(hash_args: &HashArgs, verbose: bool) {
    let algorithm = hash_args.algorithm.unwrap_or(HashAlgorithm::SHA256);
    let file_list: Vec<PathBuf> = hash_args
        .files
        .iter()
        .filter(|p| {
            p.try_exists()
                .inspect_err(|e| {
                    eprintln!("Failed to read file or directory {}: {}", p.display(), e)
                })
                .unwrap_or(false)
                && p.is_file()
        })
        .filter_map(|p| {
            dunce::canonicalize(p)
                .inspect_err(|e| {
                    eprintln!("Failed to read file or directory {}: {}", p.display(), e)
                })
                .ok()
        })
        .unique()
        .collect();
    let mut hasher: Box<dyn DynDigest> = get_algorithm_hasher!(algorithm);

    for path in file_list {
        let pathname = &path.display();
        vprintln!(verbose, "Hashing file {}", pathname);
        let file = unwrap_continue!(File::open(&path), |e| {
            eprintln!("Error opening file {}: {}", pathname, e);
        });
        let mut reader = BufReader::with_capacity(BUF_LENGTH, file);

        loop {
            let length = {
                let buffer = unwrap_continue!(reader.fill_buf(), |e| {
                    eprintln!("Error reading from file {}: {}", pathname, e);
                });
                let len = buffer.len();
                if len > 0 {
                    hasher.update(buffer);
                    vprintln!(verbose, "Read block: {} bytes", len);
                }
                len
            };

            if length == 0 {
                break;
            }

            reader.consume(length);
        }

        let result = hasher.finalize_reset();

        println!(
            "[{}] {}: {}",
            get_algorithm_string!(algorithm),
            pathname,
            hex::encode(result)
        );
    }
}
