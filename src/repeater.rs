use bip39::Mnemonic;
use sha2::{Sha256, Digest};

pub fn get_repeated(s: String, min_bytes: usize) -> Vec<u8> {
    let bytes = s.into_bytes();
    let mut repeated = Vec::new();
    let times = min_bytes / bytes.len();
    let remainder = min_bytes % bytes.len();
    for _ in 0..times {
        repeated.extend_from_slice(&bytes);
    }
    repeated.extend_from_slice(&bytes[..remainder]);
    repeated
}

pub fn get_hashed(s: Vec<u8>, min_bytes: usize) -> Vec<u8> {
    let min_hash_times = min_bytes / 32;
    let must_end_with: [u8; 8] = (min_bytes as u64).to_be_bytes();
    let must_end_with: [u8; 1] = must_end_with[7..8].to_vec().try_into().unwrap();
    let mut first_serial_hashes = Vec::new();
    let mut hasher = Sha256::new();
    hasher.update(&s);
    for _ in 0..min_hash_times - 1 {
        first_serial_hashes.extend_from_slice(&hasher.finalize_reset());
    }
    let mut last_hash;
    loop {
        hasher.update(&first_serial_hashes);
        last_hash = hasher.finalize_reset();
        if last_hash.ends_with(&must_end_with) {
            break;
        }
        first_serial_hashes.extend_from_slice(&last_hash);
    }
    first_serial_hashes.extend_from_slice(&last_hash);
    first_serial_hashes[0..min_bytes].to_vec()
}

pub fn mnemonic_to_string(mnemonic: &Mnemonic) -> String {
    mnemonic.word_iter().map(|a| a.to_string()).reduce(|a, b| format!("{} {}", a, b)).unwrap().to_owned()
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use crate::repeater::get_hashed;

    #[test]
    fn test_get_repeated() {
        let s = "abc".to_string();
        let min_bytes = 10;
        let repeated = super::get_repeated(s, min_bytes);
        assert_eq!(repeated, vec![97, 98, 99, 97, 98, 99, 97, 98, 99, 97]);
    }

    #[test]
    fn test_can_get_mnemonic() {
        let hashed = get_hashed(vec![97, 98, 99, 97, 98, 99, 97, 98, 99, 97], 32);
        let mnemonic = Mnemonic::from_entropy(&hashed).unwrap();
        let mnemonic = super::mnemonic_to_string(&mnemonic);
        assert_eq!(mnemonic, "tell bundle urge hero cattle question animal unaware season before nephew ability drift slush tumble market century region toward buyer sustain suspect desk test");
    }
}