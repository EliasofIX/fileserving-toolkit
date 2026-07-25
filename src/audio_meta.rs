//! Read embedded audio tags (artist) for the music player.

use crate::crypto::{self, EncryptedReader};
use lofty::file::{FileType, TaggedFile};
use lofty::prelude::*;
use lofty::probe::Probe;
use lofty::read_from_path;
use std::io::Cursor;
use std::path::Path;

/// Max plaintext prefix decrypted for tag probing on encrypted files.
/// Tags for common formats live near the start; one crypto chunk is enough.
const META_PREFIX_MAX: u64 = crypto::CHUNK_PLAIN;

/// Primary-tag artist only. Fail soft: probe/tag errors → `None`.
pub fn read_artist(path: &Path) -> Option<String> {
    let tagged = read_from_path(path).ok()?;
    artist_from_tagged(&tagged)
}

/// Read artist from an encrypted file without writing plaintext to disk.
/// Decrypts at most the first [`META_PREFIX_MAX`] plaintext bytes into memory.
pub fn read_artist_encrypted(enc: &Path, dk_bytes: &[u8], name_hint: &str) -> Option<String> {
    let mut reader = EncryptedReader::open(enc, dk_bytes).ok()?;
    let plain_size = reader.plain_size.unwrap_or(META_PREFIX_MAX);
    let end = plain_size.min(META_PREFIX_MAX);
    let mut buf = Vec::new();
    reader.read_plain_range(0, end, &mut buf).ok()?;
    read_artist_from_bytes(&buf, name_hint)
}

fn read_artist_from_bytes(data: &[u8], name_hint: &str) -> Option<String> {
    let cursor = Cursor::new(data);
    let probe = if let Some(ft) = FileType::from_path(name_hint) {
        Probe::new(cursor).set_file_type(ft)
    } else {
        Probe::new(cursor).guess_file_type().ok()?
    };
    let tagged = probe.read().ok()?;
    artist_from_tagged(&tagged)
}

fn artist_from_tagged(tagged: &TaggedFile) -> Option<String> {
    let tag = tagged.primary_tag().or_else(|| tagged.first_tag())?;
    let artist = tag.artist()?;
    let trimmed = artist.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lofty::config::WriteOptions;
    use lofty::tag::{Tag, TagType};
    use std::fs;

    fn silence_wav() -> Vec<u8> {
        let rate: u32 = 8000;
        let n: u32 = 800;
        let data_len = n * 2;
        let mut wav = Vec::with_capacity(44 + data_len as usize);
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data_len).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
        wav.extend_from_slice(&1u16.to_le_bytes()); // mono
        wav.extend_from_slice(&rate.to_le_bytes());
        wav.extend_from_slice(&(rate * 2).to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&data_len.to_le_bytes());
        wav.resize(wav.len() + data_len as usize, 0);
        wav
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fst-audio-meta-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn reads_tagged_artist() {
        let dir = tempfile_dir();
        let path = dir.join("tagged.wav");
        fs::write(&path, silence_wav()).unwrap();

        let mut tagged = read_from_path(&path).expect("probe wav");
        let mut tag = Tag::new(TagType::Id3v2);
        tag.set_artist(String::from("Miles Davis"));
        tagged.insert_tag(tag);
        tagged
            .save_to_path(&path, WriteOptions::default())
            .expect("write tags");

        assert_eq!(read_artist(&path).as_deref(), Some("Miles Davis"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn untagged_returns_none() {
        let dir = tempfile_dir();
        let path = dir.join("untagged.wav");
        fs::write(&path, silence_wav()).unwrap();
        assert_eq!(read_artist(&path), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_returns_none() {
        let dir = tempfile_dir();
        let path = dir.join("nope.mp3");
        assert_eq!(read_artist(&path), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_artist_from_bytes_prefix() {
        let dir = tempfile_dir();
        let path = dir.join("tagged.wav");
        fs::write(&path, silence_wav()).unwrap();
        let mut tagged = read_from_path(&path).expect("probe wav");
        let mut tag = Tag::new(TagType::Id3v2);
        tag.set_artist(String::from("Bill Evans"));
        tagged.insert_tag(tag);
        tagged
            .save_to_path(&path, WriteOptions::default())
            .expect("write tags");
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            read_artist_from_bytes(&bytes, "tagged.wav").as_deref(),
            Some("Bill Evans")
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
