//! Read embedded audio tags (artist) for the music player.

use lofty::prelude::*;
use lofty::read_from_path;
use std::path::Path;

/// Primary-tag artist only. Fail soft: probe/tag errors → `None`.
pub fn read_artist(path: &Path) -> Option<String> {
    let tagged = read_from_path(path).ok()?;
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

    #[test]
    fn reads_tagged_artist() {
        let p = Path::new("/tmp/fst-audio-test/tagged.wav");
        assert_eq!(read_artist(p).as_deref(), Some("Miles Davis"));
    }

    #[test]
    fn untagged_returns_none() {
        let p = Path::new("/tmp/fst-audio-test/untagged.wav");
        assert_eq!(read_artist(p), None);
    }

    #[test]
    fn missing_file_returns_none() {
        assert_eq!(read_artist(Path::new("/tmp/fst-audio-test/nope.mp3")), None);
    }
}
