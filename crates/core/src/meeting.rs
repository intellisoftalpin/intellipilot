//! Project meeting domain types and pure rules (transcript conversion).

use serde::Serialize;
use time::{Date, OffsetDateTime, Time};
use utoipa::ToSchema;
use uuid::Uuid;

/// What a file is to its meeting. Stored in `attachments.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// An audio or video recording.
    Recording,
    /// The original transcript file (its text is also on the meeting).
    Transcript,
    /// The original summary file (its text is also on the meeting).
    Summary,
    /// Anything else: slides, documents, images.
    Other,
}

impl ArtifactKind {
    /// Parse the wire / stored form.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "recording" => Self::Recording,
            "transcript" => Self::Transcript,
            "summary" => Self::Summary,
            "other" => Self::Other,
            _ => return None,
        })
    }

    /// The wire / stored form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Transcript => "transcript",
            Self::Summary => "summary",
            Self::Other => "other",
        }
    }
}

/// A meeting with its minutes and links.
///
/// `meeting_date`, `start_time` and `end_time` are local to `timezone` and
/// never converted: the calendar shows a meeting on the date it was entered.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Meeting {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    /// ISO `YYYY-MM-DD`.
    #[schema(value_type = String)]
    #[serde(with = "crate::serde_date::required")]
    pub meeting_date: Date,
    /// Local `HH:MM`, or null.
    #[schema(value_type = Option<String>)]
    #[serde(with = "serde_hm::option")]
    pub start_time: Option<Time>,
    /// Local `HH:MM`, or null. Only set together with `start_time`.
    #[schema(value_type = Option<String>)]
    #[serde(with = "serde_hm::option")]
    pub end_time: Option<Time>,
    /// IANA zone name the times are expressed in, e.g. `Europe/Zurich`.
    pub timezone: String,
    /// Room, address or call link. Empty when unset.
    pub location: String,
    /// Agenda / notes (markdown). Empty when unset.
    pub description: String,
    /// Meeting summary (markdown). Empty when unset.
    pub summary: String,
    /// Full plain-text transcript. Empty when unset.
    pub transcript: String,
    pub created_by: Option<Uuid>,
    pub participant_ids: Vec<Uuid>,
    pub issue_ids: Vec<Uuid>,
    pub epic_ids: Vec<Uuid>,
    pub customer_ids: Vec<Uuid>,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

/// A meeting as listed in the calendar: no long text, just enough to render
/// a row and badges.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MeetingListItem {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    #[schema(value_type = String)]
    #[serde(with = "crate::serde_date::required")]
    pub meeting_date: Date,
    #[schema(value_type = Option<String>)]
    #[serde(with = "serde_hm::option")]
    pub start_time: Option<Time>,
    #[schema(value_type = Option<String>)]
    #[serde(with = "serde_hm::option")]
    pub end_time: Option<Time>,
    pub timezone: String,
    pub location: String,
    pub has_summary: bool,
    pub has_transcript: bool,
    /// Number of recording files.
    pub recording_count: i64,
    /// Number of files of any kind.
    pub file_count: i64,
    pub participant_ids: Vec<Uuid>,
}

/// How many meetings fall on one calendar day.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MeetingDayCount {
    #[schema(value_type = String)]
    #[serde(with = "crate::serde_date::required")]
    pub date: Date,
    pub count: i64,
}

/// `Option<Time>` ⇄ local `HH:MM` (seconds accepted on input, dropped).
pub mod serde_hm {
    use time::Time;
    use time::format_description::FormatItem;
    use time::macros::format_description;

    const HM: &[FormatItem<'_>] = format_description!("[hour]:[minute]");
    const HMS: &[FormatItem<'_>] = format_description!("[hour]:[minute]:[second]");

    /// Parse `HH:MM` or `HH:MM:SS`; seconds are truncated.
    #[must_use]
    pub fn parse(s: &str) -> Option<Time> {
        let t = Time::parse(s, &HM).or_else(|_| Time::parse(s, &HMS)).ok()?;
        Time::from_hms(t.hour(), t.minute(), 0).ok()
    }

    /// Render as `HH:MM`.
    #[must_use]
    pub fn render(t: Time) -> String {
        t.format(&HM).unwrap_or_default()
    }

    pub mod option {
        use serde::{Deserialize, Deserializer, Serializer, de};
        use time::Time;

        #[allow(clippy::ref_option)] // serde's `with` hands us `&Option<T>`
        pub fn serialize<S: Serializer>(v: &Option<Time>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(t) => s.serialize_some(&super::render(*t)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Time>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|s| super::parse(&s).ok_or_else(|| de::Error::custom("expected HH:MM")))
                .transpose()
        }
    }

    /// `Option<Option<Time>>` for PATCH bodies: absent → `None`, `null` →
    /// `Some(None)`, `"09:30"` → `Some(Some(t))`. Pair with `#[serde(default)]`.
    pub mod double_option {
        use serde::{Deserialize, Deserializer, Serializer, de};
        use time::Time;

        #[allow(clippy::ref_option)]
        pub fn serialize<S: Serializer>(v: &Option<Option<Time>>, s: S) -> Result<S::Ok, S::Error> {
            match v.as_ref().and_then(|inner| inner.as_ref()) {
                Some(t) => s.serialize_some(&super::render(*t)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<Option<Time>>, D::Error> {
            Option::<String>::deserialize(d)?.map_or(Ok(Some(None)), |s| {
                super::parse(&s)
                    .map(|t| Some(Some(t)))
                    .ok_or_else(|| de::Error::custom("expected HH:MM"))
            })
        }
    }
}

/// Whether `end` may follow `start`: an end needs a start and must be later
/// the same day. Mirrors the table CHECK constraints so callers get a 422,
/// not a 500.
#[must_use]
pub fn times_ok(start: Option<Time>, end: Option<Time>) -> bool {
    match (start, end) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(s), Some(e)) => e > s,
    }
}

/// Text formats a transcript or summary can be imported from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFormat {
    /// `.txt` / `.md` — taken as is.
    Plain,
    /// WebVTT subtitles.
    Vtt,
    /// SubRip subtitles.
    Srt,
}

impl TextFormat {
    /// Pick the format from a file name's extension.
    #[must_use]
    pub fn from_filename(name: &str) -> Option<Self> {
        let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
        Some(match ext.as_str() {
            "txt" | "md" | "markdown" | "text" => Self::Plain,
            "vtt" => Self::Vtt,
            "srt" => Self::Srt,
            _ => return None,
        })
    }
}

/// Convert an imported transcript/summary file to plain text.
///
/// Subtitle formats lose their cue numbers, timings, headers and styling
/// tags; consecutive cues by the same `<v Speaker>` voice are kept on
/// separate lines, and a voice tag becomes a `Speaker: ` prefix. Line endings
/// are normalized to `\n` and a UTF-8 BOM is dropped.
#[must_use]
pub fn to_plain_text(raw: &str, format: TextFormat) -> String {
    let text = raw
        .strip_prefix('\u{feff}')
        .unwrap_or(raw)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    match format {
        TextFormat::Plain => text.trim().to_owned(),
        TextFormat::Vtt | TextFormat::Srt => subtitles_to_text(&text, format == TextFormat::Vtt),
    }
}

fn subtitles_to_text(text: &str, vtt: bool) -> String {
    let mut out: Vec<String> = Vec::new();
    // Skip whole blocks that are metadata rather than cues (VTT header,
    // NOTE/STYLE/REGION blocks).
    for block in text.split("\n\n") {
        let lines: Vec<&str> = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let Some(first) = lines.first() else {
            continue;
        };
        if vtt
            && (first.starts_with("WEBVTT")
                || first.starts_with("NOTE")
                || first.starts_with("STYLE")
                || first.starts_with("REGION"))
        {
            continue;
        }
        for line in lines {
            if line.contains("-->") || line.chars().all(|c| c.is_ascii_digit()) {
                continue; // timing line or SRT cue number
            }
            let cleaned = strip_cue_tags(line);
            if !cleaned.is_empty() {
                out.push(cleaned);
            }
        }
    }
    out.join("\n")
}

/// Drop `<...>` tags, turning a leading `<v Name>` voice tag into `Name: `.
fn strip_cue_tags(line: &str) -> String {
    let mut speaker: Option<String> = None;
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(open) = rest.find('<') {
        out.push_str(rest.get(..open).unwrap_or_default());
        let after = rest.get(open..).unwrap_or_default();
        let Some(close) = after.find('>') else {
            out.push_str(after);
            rest = "";
            break;
        };
        let tag = after.get(1..close).unwrap_or_default();
        // A voice tag is `v Name` or `v.class Name`: the name follows the
        // first space.
        let is_voice = tag.starts_with("v ") || tag.starts_with("v.");
        if speaker.is_none()
            && is_voice
            && let Some((_, name)) = tag.split_once(' ')
            && !name.trim().is_empty()
        {
            speaker = Some(name.trim().to_owned());
        }
        rest = after.get(close.saturating_add(1)..).unwrap_or_default();
    }
    out.push_str(rest);
    let body = out.split_whitespace().collect::<Vec<_>>().join(" ");
    match speaker {
        Some(s) if !body.is_empty() => format!("{s}: {body}"),
        _ => body,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_and_renders_times() {
        let t = serde_hm::parse("09:30").unwrap();
        assert_eq!(serde_hm::render(t), "09:30");
        assert_eq!(
            serde_hm::render(serde_hm::parse("17:05:59").unwrap()),
            "17:05"
        );
        assert!(serde_hm::parse("25:00").is_none());
        assert!(serde_hm::parse("9h").is_none());
    }

    #[test]
    fn end_time_rules() {
        let nine = serde_hm::parse("09:00");
        let ten = serde_hm::parse("10:00");
        assert!(times_ok(None, None));
        assert!(times_ok(nine, None));
        assert!(times_ok(nine, ten));
        assert!(!times_ok(ten, nine));
        assert!(!times_ok(nine, nine));
        assert!(!times_ok(None, ten));
    }

    #[test]
    fn vtt_loses_header_timings_and_tags() {
        let vtt = "\u{feff}WEBVTT\r\nKind: captions\r\n\r\nNOTE internal\r\n\r\n1\r\n00:00:01.000 --> 00:00:04.000 align:start\r\n<v Roger Bingham>We are in New York City\r\n\r\n00:00:05.000 --> 00:00:07.000\r\n<v.loud Neil>Hi <b>there</b></v>\r\nsecond line\r\n";
        assert_eq!(
            to_plain_text(vtt, TextFormat::Vtt),
            "Roger Bingham: We are in New York City\nNeil: Hi there\nsecond line"
        );
    }

    #[test]
    fn srt_loses_numbers_and_timings() {
        let srt = "1\n00:00:01,000 --> 00:00:02,000\nHello\n\n2\n00:00:03,000 --> 00:00:04,000\n<i>World</i>\n";
        assert_eq!(to_plain_text(srt, TextFormat::Srt), "Hello\nWorld");
    }

    #[test]
    fn plain_text_is_trimmed_and_normalized() {
        assert_eq!(to_plain_text("  a\r\nb \n", TextFormat::Plain), "a\nb");
    }

    #[test]
    fn format_from_filename() {
        assert_eq!(TextFormat::from_filename("x.VTT"), Some(TextFormat::Vtt));
        assert_eq!(
            TextFormat::from_filename("notes.md"),
            Some(TextFormat::Plain)
        );
        assert_eq!(TextFormat::from_filename("a.srt"), Some(TextFormat::Srt));
        assert_eq!(TextFormat::from_filename("a.pdf"), None);
        assert_eq!(TextFormat::from_filename("noext"), None);
    }

    #[test]
    fn artifact_kinds_round_trip() {
        for k in [
            ArtifactKind::Recording,
            ArtifactKind::Transcript,
            ArtifactKind::Summary,
            ArtifactKind::Other,
        ] {
            assert_eq!(ArtifactKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(ArtifactKind::parse("video"), None);
    }
}
