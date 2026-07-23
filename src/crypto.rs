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
pub const VERSION: u8 = 2;
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

/// Wrap an existing DEK to a second recipient's EK (admin dual-access).
fn wrap_dek_for_ek(dek: &Dek, ek_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let ek = decode_ek(ek_bytes)?;
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::Msg("wrap encapsulate failed".into()))?;
    let hk = Hkdf::<Sha256>::new(None, ss.as_ref());
    let mut wrap_key = [0u8; 32];
    hk.expand(b"fst-wrap-v1", &mut wrap_key)
        .map_err(|e| CryptoError::Msg(e.to_string()))?;
    let cipher =
        Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| CryptoError::Msg(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let edek = cipher
        .encrypt(Nonce::from_slice(&nonce), dek.0.as_ref())
        .map_err(|e| CryptoError::Msg(e.to_string()))?;
    let mut blob = Vec::with_capacity(4 + ct.len() + 12 + edek.len());
    blob.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    blob.extend_from_slice(ct.as_ref());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&edek);
    Ok(blob)
}

fn unwrap_dek_from_blob(dk_bytes: &[u8], blob: &[u8]) -> Result<Dek, CryptoError> {
    if blob.len() < 4 + 12 + TAG_LEN {
        return Err(CryptoError::Msg("bad wrap blob".into()));
    }
    let ct_len = u32::from_be_bytes(blob[0..4].try_into().unwrap()) as usize;
    if blob.len() < 4 + ct_len + 12 + TAG_LEN {
        return Err(CryptoError::Msg("bad wrap blob len".into()));
    }
    let ct = &blob[4..4 + ct_len];
    let nonce = &blob[4 + ct_len..4 + ct_len + 12];
    let edek = &blob[4 + ct_len + 12..];
    let dk = decode_dk(dk_bytes)?;
    let ct_arr: Ciphertext<MlKem768> = ct
        .try_into()
        .map_err(|_| CryptoError::Msg("bad wrap kem ct".into()))?;
    let ss = dk
        .decapsulate(&ct_arr)
        .map_err(|_| CryptoError::Msg("wrap decapsulate failed".into()))?;
    let hk = Hkdf::<Sha256>::new(None, ss.as_ref());
    let mut wrap_key = [0u8; 32];
    hk.expand(b"fst-wrap-v1", &mut wrap_key)
        .map_err(|e| CryptoError::Msg(e.to_string()))?;
    let cipher =
        Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| CryptoError::Msg(e.to_string()))?;
    let dek_bytes = cipher
        .decrypt(Nonce::from_slice(nonce), edek)
        .map_err(|e| CryptoError::Msg(format!("unwrap: {e}")))?;
    let mut dek = [0u8; 32];
    if dek_bytes.len() != 32 {
        return Err(CryptoError::Msg("bad unwrapped dek".into()));
    }
    dek.copy_from_slice(&dek_bytes);
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

/// Encrypt plaintext file → encrypted path (streaming, framed) with optional admin wrap.
/// Writes via a temp file then renames so a stale `.fst-idx` can never pair with new ciphertext.
pub fn encrypt_file(
    plain: &Path,
    out: &Path,
    ek_bytes: &[u8],
    secondary_ek: Option<&[u8]>,
) -> Result<(), CryptoError> {
    use std::io::{Read, Seek, Write};
    let (kem_ct, dek) = encapsulate_dek(ek_bytes)?;
    let wrap2 = match secondary_ek {
        Some(ek) => wrap_dek_for_ek(&dek, ek)?,
        None => Vec::new(),
    };
    let cipher = Aes256Gcm::new_from_slice(&dek.0).map_err(|e| CryptoError::Msg(e.to_string()))?;

    // Keep existing out + sidecars intact until the new ciphertext is renamed into place.
    let mut tmp_os = out.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    let _ = std::fs::remove_file(&tmp);

    let result = (|| -> Result<Vec<u64>, CryptoError> {
        let mut inp = std::fs::File::open(plain)?;
        let mut outf = std::fs::File::create(&tmp)?;
        outf.write_all(MAGIC)?;
        outf.write_all(&[VERSION])?;
        outf.write_all(&(kem_ct.len() as u32).to_be_bytes())?;
        outf.write_all(&kem_ct)?;
        outf.write_all(&(wrap2.len() as u32).to_be_bytes())?;
        outf.write_all(&wrap2)?;

        let mut frame_offsets: Vec<u64> = Vec::new();
        let mut buf = vec![0u8; CHUNK_PLAIN as usize];
        let mut index: u64 = 0;
        loop {
            let n = inp.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let offset = outf.stream_position()?;
            frame_offsets.push(offset);
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
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
        Ok(frame_offsets)
    })();

    let frame_offsets = match result {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };

    // Stage the frame index against the temp ciphertext first so index IO
    // failures leave the existing `out` + sidecars untouched.
    let staged_idx = index_path_for(&tmp);
    if let Err(e) = write_frame_index(&tmp, &frame_offsets) {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&staged_idx);
        return Err(e);
    }

    std::fs::rename(&tmp, out)?;
    let final_idx = index_path_for(out);
    let _ = std::fs::remove_file(&final_idx);
    if let Err(e) = std::fs::rename(&staged_idx, &final_idx) {
        let _ = std::fs::remove_file(&staged_idx);
        // Cipher is committed; re-write index at the final path (same blob).
        if let Err(e2) = write_frame_index(out, &frame_offsets) {
            let _ = std::fs::remove_file(&final_idx);
            let _ = std::fs::remove_file(meta_path(out));
            return Err(CryptoError::Msg(format!(
                "index install after rename failed: {e}; rewrite: {e2}"
            )));
        }
    }
    // Invalidate stale plain-size meta; seal_uploaded_file rewrites it on success.
    let _ = std::fs::remove_file(meta_path(out));
    Ok(())
}

fn write_frame_index(enc: &Path, offsets: &[u64]) -> Result<(), CryptoError> {
    let mut blob = Vec::with_capacity(8 + offsets.len() * 8);
    blob.extend_from_slice(&(offsets.len() as u64).to_le_bytes());
    for o in offsets {
        blob.extend_from_slice(&o.to_le_bytes());
    }
    let idx = index_path_for(enc);
    let mut tmp_os = idx.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    std::fs::write(&tmp, &blob)?;
    std::fs::rename(tmp, idx)?;
    Ok(())
}

fn read_frame_index(enc: &Path) -> Option<Vec<u64>> {
    let blob = std::fs::read(index_path_for(enc)).ok()?;
    if blob.len() < 8 {
        return None;
    }
    let n = u64::from_le_bytes(blob[0..8].try_into().ok()?) as usize;
    if blob.len() < 8 + n * 8 {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let s = 8 + i * 8;
        out.push(u64::from_le_bytes(blob[s..s + 8].try_into().ok()?));
    }
    Some(out)
}

fn open_header_and_dek(
    file: &mut std::fs::File,
    dk_bytes: &[u8],
) -> Result<(u8, u64, Dek), CryptoError> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    let mut ver = [0u8; 1];
    file.read_exact(&mut ver)?;
    let version = ver[0];
    let mut len_b = [0u8; 4];
    file.read_exact(&mut len_b)?;
    let kem_len = u32::from_be_bytes(len_b) as usize;
    let mut kem_ct = vec![0u8; kem_len];
    file.read_exact(&mut kem_ct)?;

    let mut header_len = 4 + 1 + 4 + kem_len as u64;
    let mut wrap2 = Vec::new();
    if version >= 2 {
        let mut wlen_b = [0u8; 4];
        file.read_exact(&mut wlen_b)?;
        let wlen = u32::from_be_bytes(wlen_b) as usize;
        wrap2.resize(wlen, 0);
        if wlen > 0 {
            file.read_exact(&mut wrap2)?;
        }
        header_len += 4 + wlen as u64;
    }

    // Prefer secondary wrap when present: ML-KEM decapsulate is infallible for
    // wrong keys (returns garbage SS), so trying primary first would hide wrap2.
    let dek = if !wrap2.is_empty() {
        match unwrap_dek_from_blob(dk_bytes, &wrap2) {
            Ok(d) => d,
            Err(_) => decapsulate_dek(dk_bytes, &kem_ct)?,
        }
    } else {
        decapsulate_dek(dk_bytes, &kem_ct)?
    };
    Ok((version, header_len, dek))
}

/// Decrypt entire file to plaintext path (utility / tests).
#[allow(dead_code)]
pub fn decrypt_file(enc: &Path, out: &Path, dk_bytes: &[u8]) -> Result<(), CryptoError> {
    use std::io::{Read, Write};
    let mut inp = std::fs::File::open(enc)?;
    let (_ver, _header_len, dek) = open_header_and_dek(&mut inp, dk_bytes)?;
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
    }
    outf.sync_all()?;
    Ok(())
}

/// Open encrypted file for streaming decrypt of a plaintext byte range.
pub struct EncryptedReader {
    file: std::fs::File,
    cipher: Aes256Gcm,
    header_len: u64,
    frame_offsets: Vec<u64>,
    pub plain_size: Option<u64>,
}

impl EncryptedReader {
    pub fn open(path: &Path, dk_bytes: &[u8]) -> Result<Self, CryptoError> {
        use std::io::{Seek, SeekFrom};
        let mut file = std::fs::File::open(path)?;
        let (_ver, header_len, dek) = open_header_and_dek(&mut file, dk_bytes)?;
        let cipher =
            Aes256Gcm::new_from_slice(&dek.0).map_err(|e| CryptoError::Msg(e.to_string()))?;

        let file_len = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(header_len))?;
        let body = file_len.saturating_sub(header_len);
        let frame_full = CHUNK_PLAIN + FRAME_OVERHEAD;
        let plain_size = if body == 0 {
            Some(0)
        } else if let Some(s) = read_plain_size_meta(path) {
            Some(s)
        } else {
            let n_full = body / frame_full;
            let rem = body % frame_full;
            if rem == 0 {
                Some(n_full * CHUNK_PLAIN)
            } else {
                Some(n_full * CHUNK_PLAIN + rem.saturating_sub(FRAME_OVERHEAD))
            }
        };

        let mut frame_offsets = read_frame_index(path).unwrap_or_default();
        // Discard index if it disagrees with known plaintext size (stale sidecar).
        if let Some(ps) = plain_size {
            let expected = if ps == 0 {
                0
            } else {
                (ps + CHUNK_PLAIN - 1) / CHUNK_PLAIN
            };
            if !frame_offsets.is_empty() && frame_offsets.len() as u64 != expected {
                tracing::warn!(
                    "ignoring stale frame index for {} ({} frames, expected {expected})",
                    path.display(),
                    frame_offsets.len()
                );
                frame_offsets.clear();
            }
        }

        Ok(Self {
            file,
            cipher,
            header_len,
            frame_offsets,
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

        if !self.frame_offsets.is_empty() {
            if first_chunk as usize >= self.frame_offsets.len() {
                return Ok(());
            }
            for chunk_i in first_chunk..=last_chunk {
                let Some(&off) = self.frame_offsets.get(chunk_i as usize) else {
                    break;
                };
                self.file.seek(SeekFrom::Start(off))?;
                let mut idx_b = [0u8; 8];
                self.file.read_exact(&mut idx_b)?;
                let mut len_b = [0u8; 4];
                self.file.read_exact(&mut len_b)?;
                let pt_len = u32::from_be_bytes(len_b) as usize;
                let mut nonce = [0u8; 12];
                self.file.read_exact(&mut nonce)?;
                let mut ct = vec![0u8; pt_len + TAG_LEN];
                self.file.read_exact(&mut ct)?;
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
            return Ok(());
        }

        // Fallback scan (v1 files without index) — skip frames until first_chunk
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

            if chunk_i >= first_chunk {
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
        }
        Ok(())
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
    secondary_ek: Option<&[u8]>,
    plain_size: u64,
) -> Result<(), CryptoError> {
    encrypt_file(temp_plain, final_enc, ek_bytes, secondary_ek)?;
    write_plain_size_meta(final_enc, plain_size)?;
    Ok(())
}

pub fn keystore_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("keystore")
}
