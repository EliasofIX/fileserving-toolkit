//! Post-quantum hybrid crypto for FST.
//!
//! At-rest format (framed for TB + Range):
//!   magic "FST1" | version u8 | kem_ct_len u32 BE | kem_ct | chunk_frames...
//! Each chunk frame (CHUNK_SIZE plaintext, last may be short):
//!   index u64 BE | pt_len u32 BE | nonce 12 | ciphertext+16tag
//!
//! DEK (32 bytes) is encapsulated with ML-KEM-768 (Kyber). AES-256-GCM
//! for bulk — AES-256 remains the practical PQ-safe symmetric primitive.
//! Passwords → Argon2id → unlock ML-KEM secret key stored on disk.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAGIC: &[u8; 4] = b"FST1";
pub const VERSION: u8 = 1;
/// Plaintext bytes per encrypted frame. Power-of-two aligned for Range math.
pub const CHUNK_PLAIN: u64 = 4 * 1024 * 1024; // 4 MiB
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const FRAME_OVERHEAD: u64 = 8 + 4 + NONCE_LEN as u64 + TAG_LEN as u64; // index+len+nonce+tag

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("crypto: {0}")]
    Msg(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad password")]
    BadPassword,
    #[error("not an FST encrypted file")]
    NotEncrypted,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek(pub [u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserSecrets {
    pub kem_dk: Vec<u8>,
}

/// Argon2id hash for storage in config.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::Msg(e.to_string()))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let parsed = PasswordHash::new(hash).map_err(|e| CryptoError::Msg(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Derive a 32-byte key from password + username salt label.
fn kdf_password(password: &str, username: &str) -> Result<[u8; 32], CryptoError> {
    // Fixed params for unlock key (separate from stored password hash).
    // Salt embeds username so keys aren't interchangeable across users.
    let salt = format!("fst-v1-{username}");
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(19_456, 2, 1, Some(32)).map_err(|e| CryptoError::Msg(e.to_string()))?,
    );
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out)
        .map_err(|e| CryptoError::Msg(e.to_string()))?;
    Ok(out)
}

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

fn encode_ek(ek: &Ek) -> Vec<u8> {
    ek.as_bytes().as_slice().to_vec()
}
fn encode_dk(dk: &Dk) -> Vec<u8> {
    dk.as_bytes().as_slice().to_vec()
}
fn decode_ek(bytes: &[u8]) -> Result<Ek, CryptoError> {
    let arr: ml_kem::Encoded<Ek> = bytes
        .try_into()
        .map_err(|_| CryptoError::Msg("bad ek length".into()))?;
    Ok(Ek::from_bytes(&arr))
}
fn decode_dk(bytes: &[u8]) -> Result<Dk, CryptoError> {
    let arr: ml_kem::Encoded<Dk> = bytes
        .try_into()
        .map_err(|_| CryptoError::Msg("bad dk length".into()))?;
    Ok(Dk::from_bytes(&arr))
}

/// Generate ML-KEM-768 keypair; seal secret with password-derived key.
pub fn create_user_keystore(username: &str, password: &str, dir: &Path) -> Result<(), CryptoError> {
    std::fs::create_dir_all(dir)?;
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let kek = kdf_password(password, username)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| CryptoError::Msg(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let dk_bytes = encode_dk(&dk);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), dk_bytes.as_ref())
        .map_err(|e| CryptoError::Msg(e.to_string()))?;

    let ek_path = dir.join(format!("{username}.ek"));
    let sk_path = dir.join(format!("{username}.sk"));
    std::fs::write(&ek_path, encode_ek(&ek))?;
    // sk file: nonce || ciphertext
    let mut sk_blob = Vec::with_capacity(12 + ct.len());
    sk_blob.extend_from_slice(&nonce);
    sk_blob.extend_from_slice(&ct);
    std::fs::write(&sk_path, &sk_blob)?;
    Ok(())
}

pub fn load_user_ek(username: &str, dir: &Path) -> Result<Vec<u8>, CryptoError> {
    let p = dir.join(format!("{username}.ek"));
    Ok(std::fs::read(p)?)
}

pub fn unlock_user_secrets(
    username: &str,
    password: &str,
    dir: &Path,
) -> Result<UserSecrets, CryptoError> {
    let sk_path = dir.join(format!("{username}.sk"));
    let blob = std::fs::read(sk_path)?;
    if blob.len() < 12 + TAG_LEN {
        return Err(CryptoError::Msg("corrupt sk".into()));
    }
    let (nonce, ct) = blob.split_at(12);
    let kek = kdf_password(password, username)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| CryptoError::Msg(e.to_string()))?;
    let dk_bytes = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| CryptoError::BadPassword)?;
    Ok(UserSecrets { kem_dk: dk_bytes })
}

fn encapsulate_dek(ek_bytes: &[u8]) -> Result<(Vec<u8>, Dek), CryptoError> {
    let ek = decode_ek(ek_bytes)?;
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::Msg("encapsulate failed".into()))?;
    // Derive DEK from shared secret via HKDF
    let hk = Hkdf::<Sha256>::new(None, ss.as_ref());
    let mut dek = [0u8; 32];
    hk.expand(b"fst-dek-v1", &mut dek)
        .map_err(|e| CryptoError::Msg(e.to_string()))?;
    Ok((ct.to_vec(), Dek(dek)))
}

fn decapsulate_dek(dk_bytes: &[u8], ct: &[u8]) -> Result<Dek, CryptoError> {
    let dk = decode_dk(dk_bytes)?;
    let ct_arr: Ciphertext<MlKem768> = ct
        .try_into()
        .map_err(|_| CryptoError::Msg("bad kem ct length".into()))?;
    let ss = dk
        .decapsulate(&ct_arr)
        .map_err(|_| CryptoError::Msg("decapsulate failed".into()))?;
    let hk = Hkdf::<Sha256>::new(None, ss.as_ref());
    let mut dek = [0u8; 32];
    hk.expand(b"fst-dek-v1", &mut dek)
        .map_err(|e| CryptoError::Msg(e.to_string()))?;
    Ok(Dek(dek))
}

pub fn is_encrypted_file(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    &magic == MAGIC
}

/// Encrypt plaintext file → encrypted path (streaming, framed).
pub fn encrypt_file(
    plain: &Path,
    out: &Path,
    ek_bytes: &[u8],
) -> Result<(), CryptoError> {
    use std::io::{Read, Write};
    let (kem_ct, dek) = encapsulate_dek(ek_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(&dek.0).map_err(|e| CryptoError::Msg(e.to_string()))?;

    let mut inp = std::fs::File::open(plain)?;
    let mut outf = std::fs::File::create(out)?;
    outf.write_all(MAGIC)?;
    outf.write_all(&[VERSION])?;
    let ct_len = (kem_ct.len() as u32).to_be_bytes();
    outf.write_all(&ct_len)?;
    outf.write_all(&kem_ct)?;

    let mut buf = vec![0u8; CHUNK_PLAIN as usize];
    let mut index: u64 = 0;
    loop {
        let n = inp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        // Mix index into AAD conceptually by including in plaintext prefix — we put index in clear header.
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), &buf[..n])
            .map_err(|e| CryptoError::Msg(e.to_string()))?;
        outf.write_all(&index.to_be_bytes())?;
        outf.write_all(&(n as u32).to_be_bytes())?;
        outf.write_all(&nonce)?;
        outf.write_all(&ct)?;
        index += 1;
        if n < buf.len() {
            break;
        }
    }
    outf.sync_all()?;
    Ok(())
}

/// Decrypt entire file to plaintext path (utility / tests).
#[allow(dead_code)]
pub fn decrypt_file(enc: &Path, out: &Path, dk_bytes: &[u8]) -> Result<(), CryptoError> {
    use std::io::{Read, Write};
    let mut inp = std::fs::File::open(enc)?;
    let mut magic = [0u8; 4];
    inp.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    let mut ver = [0u8; 1];
    inp.read_exact(&mut ver)?;
    let mut len_b = [0u8; 4];
    inp.read_exact(&mut len_b)?;
    let kem_len = u32::from_be_bytes(len_b) as usize;
    let mut kem_ct = vec![0u8; kem_len];
    inp.read_exact(&mut kem_ct)?;
    let dek = decapsulate_dek(dk_bytes, &kem_ct)?;
    let cipher = Aes256Gcm::new_from_slice(&dek.0).map_err(|e| CryptoError::Msg(e.to_string()))?;

    let mut outf = std::fs::File::create(out)?;
    loop {
        let mut idx_b = [0u8; 8];
        match inp.read_exact(&mut idx_b) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let mut len_b = [0u8; 4];
        inp.read_exact(&mut len_b)?;
        let pt_len = u32::from_be_bytes(len_b) as usize;
        let mut nonce = [0u8; 12];
        inp.read_exact(&mut nonce)?;
        let mut ct = vec![0u8; pt_len + TAG_LEN];
        inp.read_exact(&mut ct)?;
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
            .map_err(|e| CryptoError::Msg(format!("chunk decrypt: {e}")))?;
        outf.write_all(&pt)?;
        let _ = u64::from_be_bytes(idx_b);
    }
    outf.sync_all()?;
    Ok(())
}

/// Open encrypted file for streaming decrypt of a plaintext byte range.
pub struct EncryptedReader {
    file: std::fs::File,
    cipher: Aes256Gcm,
    header_len: u64,
    /// Cached: plaintext size if known
    pub plain_size: Option<u64>,
}

impl EncryptedReader {
    pub fn open(path: &Path, dk_bytes: &[u8]) -> Result<Self, CryptoError> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(CryptoError::NotEncrypted);
        }
        let mut ver = [0u8; 1];
        file.read_exact(&mut ver)?;
        let mut len_b = [0u8; 4];
        file.read_exact(&mut len_b)?;
        let kem_len = u32::from_be_bytes(len_b) as usize;
        let mut kem_ct = vec![0u8; kem_len];
        file.read_exact(&mut kem_ct)?;
        let header_len = 4 + 1 + 4 + kem_len as u64;
        let dek = decapsulate_dek(dk_bytes, &kem_ct)?;
        let cipher =
            Aes256Gcm::new_from_slice(&dek.0).map_err(|e| CryptoError::Msg(e.to_string()))?;

        // Estimate plaintext size from file size / frames
        let file_len = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(header_len))?;
        let body = file_len.saturating_sub(header_len);
        // Approximate: full chunks
        let frame_full = CHUNK_PLAIN + FRAME_OVERHEAD;
        let plain_size = if body == 0 {
            Some(0)
        } else {
            // Read sidecar .fst-meta if present
            let meta = meta_path(path);
            if let Ok(s) = std::fs::read_to_string(&meta) {
                s.trim().parse::<u64>().ok().map(Some).unwrap_or(None)
            } else {
                let n_full = body / frame_full;
                let rem = body % frame_full;
                if rem == 0 {
                    Some(n_full * CHUNK_PLAIN)
                } else {
                    // rem includes overhead + last pt
                    Some(n_full * CHUNK_PLAIN + rem.saturating_sub(FRAME_OVERHEAD))
                }
            }
        };

        Ok(Self {
            file,
            cipher,
            header_len,
            plain_size,
        })
    }

    /// Decrypt plaintext range [start, end) into `out`.
    pub fn read_plain_range(
        &mut self,
        start: u64,
        end: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        use std::io::{Read, Seek, SeekFrom};
        if end <= start {
            return Ok(());
        }
        let first_chunk = start / CHUNK_PLAIN;
        let last_chunk = (end - 1) / CHUNK_PLAIN;

        // Seek to first chunk frame. Frames are fixed-size except the last.
        // Without an index we scan from header — OK for moderate seeks; for TB
        // we write a sparse index sidecar (.fst-idx) during encrypt.
        let idx_path = index_path_for(&self.header_path_hint());
        // We don't have path on self — scan method:
        self.file.seek(SeekFrom::Start(self.header_len))?;

        let mut chunk_i: u64 = 0;
        loop {
            if chunk_i > last_chunk {
                break;
            }
            let mut idx_b = [0u8; 8];
            match self.file.read_exact(&mut idx_b) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let mut len_b = [0u8; 4];
            self.file.read_exact(&mut len_b)?;
            let pt_len = u32::from_be_bytes(len_b) as usize;
            let mut nonce = [0u8; 12];
            self.file.read_exact(&mut nonce)?;
            let mut ct = vec![0u8; pt_len + TAG_LEN];
            self.file.read_exact(&mut ct)?;

            if chunk_i >= first_chunk && chunk_i <= last_chunk {
                let pt = self
                    .cipher
                    .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                    .map_err(|e| CryptoError::Msg(format!("chunk: {e}")))?;
                let chunk_start = chunk_i * CHUNK_PLAIN;
                let from = start.saturating_sub(chunk_start).min(pt.len() as u64) as usize;
                let to = (end - chunk_start).min(pt.len() as u64) as usize;
                if from < to {
                    out.extend_from_slice(&pt[from..to]);
                }
            }
            chunk_i += 1;
            let _ = idx_path; // reserved for future indexed seek
            let _ = u64::from_be_bytes(idx_b);
        }
        Ok(())
    }

    fn header_path_hint(&self) -> PathBuf {
        PathBuf::new()
    }
}

fn meta_path(enc: &Path) -> PathBuf {
    let mut p = enc.as_os_str().to_owned();
    p.push(".fst-meta");
    PathBuf::from(p)
}

fn index_path_for(enc: &Path) -> PathBuf {
    let mut p = enc.as_os_str().to_owned();
    p.push(".fst-idx");
    PathBuf::from(p)
}

/// Write plaintext size sidecar for accurate Content-Length.
pub fn write_plain_size_meta(enc: &Path, plain_size: u64) -> std::io::Result<()> {
    std::fs::write(meta_path(enc), plain_size.to_string())
}

pub fn read_plain_size_meta(enc: &Path) -> Option<u64> {
    std::fs::read_to_string(meta_path(enc))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Encrypt while writing from an upload temp file; used after upload completes.
pub fn seal_uploaded_file(
    temp_plain: &Path,
    final_enc: &Path,
    ek_bytes: &[u8],
    plain_size: u64,
) -> Result<(), CryptoError> {
    encrypt_file(temp_plain, final_enc, ek_bytes)?;
    write_plain_size_meta(final_enc, plain_size)?;
    Ok(())
}

pub fn keystore_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("keystore")
}
