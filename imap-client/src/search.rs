//! Builders for IMAP `SEARCH` / `UID SEARCH` criteria.

/// A single search criterion in an IMAP `SEARCH` command.
#[derive(Debug, Clone)]
pub enum SearchKey {
    /// `FROM` — messages whose `From` header contains the substring.
    From(String),
    /// `TO` — messages whose `To` header contains the substring.
    To(String),
    /// `SUBJECT` — messages whose `Subject` header contains the substring.
    Subject(String),
    /// `BODY` — messages whose body contains the substring.
    Body(String),
    /// `TEXT` — messages whose header or body contains the substring.
    Text(String),
    /// `ALL` — every message in the mailbox.
    All,
    /// `ANSWERED` — messages with the `\Answered` flag.
    Answered,
    /// `DELETED` — messages with the `\Deleted` flag.
    Deleted,
    /// `DRAFT` — messages with the `\Draft` flag.
    Draft,
    /// `FLAGGED` — messages with the `\Flagged` flag.
    Flagged,
    /// `RECENT` — messages with the `\Recent` flag.
    Recent,
    /// `SEEN` — messages with the `\Seen` flag.
    Seen,
    /// `UNANSWERED` — messages without the `\Answered` flag.
    Unanswered,
    /// `UNDELETED` — messages without the `\Deleted` flag.
    Undeleted,
    /// `UNDRAFT` — messages without the `\Draft` flag.
    Undraft,
    /// `UNFLAGGED` — messages without the `\Flagged` flag.
    Unflagged,
    /// `UNSEEN` — messages without the `\Seen` flag.
    Unseen,
    /// Conjunction — all of the contained keys must match (space-joined).
    And(Vec<SearchKey>),
    /// `OR` — either of the two keys must match.
    Or(Box<SearchKey>, Box<SearchKey>),
    /// `NOT` — the contained key must not match.
    Not(Box<SearchKey>),
}

impl SearchKey {
    /// Render this criterion as an IMAP search-key string suitable for a
    /// `SEARCH` command.
    pub fn to_imap_string(&self) -> String {
        match self {
            SearchKey::From(s) => format!("FROM \"{}\"", s),
            SearchKey::To(s) => format!("TO \"{}\"", s),
            SearchKey::Subject(s) => format!("SUBJECT \"{}\"", s),
            SearchKey::Body(s) => format!("BODY \"{}\"", s),
            SearchKey::Text(s) => format!("TEXT \"{}\"", s),
            SearchKey::All => "ALL".to_string(),
            SearchKey::Answered => "ANSWERED".to_string(),
            SearchKey::Deleted => "DELETED".to_string(),
            SearchKey::Draft => "DRAFT".to_string(),
            SearchKey::Flagged => "FLAGGED".to_string(),
            SearchKey::Recent => "RECENT".to_string(),
            SearchKey::Seen => "SEEN".to_string(),
            SearchKey::Unanswered => "UNANSWERED".to_string(),
            SearchKey::Undeleted => "UNDELETED".to_string(),
            SearchKey::Undraft => "UNDRAFT".to_string(),
            SearchKey::Unflagged => "UNFLAGGED".to_string(),
            SearchKey::Unseen => "UNSEEN".to_string(),
            SearchKey::And(keys) => keys
                .iter()
                .map(|k| k.to_imap_string())
                .collect::<Vec<_>>()
                .join(" "),
            SearchKey::Or(left, right) => format!(
                "OR ({}) ({})",
                left.to_imap_string(),
                right.to_imap_string()
            ),
            SearchKey::Not(key) => format!("NOT ({})", key.to_imap_string()),
        }
    }
}

/// A convenience builder that wraps a single [`SearchKey`] and renders it to
/// the IMAP search-key string.
pub struct SearchQuery {
    key: SearchKey,
}

impl SearchQuery {
    /// Build a query from an arbitrary [`SearchKey`] (including compound
    /// `And` / `Or` / `Not` trees).
    pub fn new(key: SearchKey) -> Self {
        Self { key }
    }

    /// Shorthand for a `FROM` search.
    pub fn from(addr: &str) -> Self {
        Self::new(SearchKey::From(addr.to_string()))
    }

    /// Shorthand for a `TO` search.
    pub fn to(addr: &str) -> Self {
        Self::new(SearchKey::To(addr.to_string()))
    }

    /// Shorthand for a `SUBJECT` search.
    pub fn subject(text: &str) -> Self {
        Self::new(SearchKey::Subject(text.to_string()))
    }

    /// Consume the builder and render the IMAP search-key string.
    pub fn build(self) -> String {
        self.key.to_imap_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_key_formatting() {
        assert_eq!(SearchKey::All.to_imap_string(), "ALL");
        assert_eq!(
            SearchKey::From("alice".into()).to_imap_string(),
            "FROM \"alice\""
        );
        assert_eq!(SearchKey::To("bob".into()).to_imap_string(), "TO \"bob\"");
        assert_eq!(
            SearchKey::Subject("hello".into()).to_imap_string(),
            "SUBJECT \"hello\""
        );
        assert_eq!(
            SearchKey::Body("world".into()).to_imap_string(),
            "BODY \"world\""
        );
        assert_eq!(
            SearchKey::Text("foo".into()).to_imap_string(),
            "TEXT \"foo\""
        );
        assert_eq!(SearchKey::Answered.to_imap_string(), "ANSWERED");
        assert_eq!(SearchKey::Deleted.to_imap_string(), "DELETED");
        assert_eq!(SearchKey::Draft.to_imap_string(), "DRAFT");
        assert_eq!(SearchKey::Flagged.to_imap_string(), "FLAGGED");
        assert_eq!(SearchKey::Recent.to_imap_string(), "RECENT");
        assert_eq!(SearchKey::Seen.to_imap_string(), "SEEN");
        assert_eq!(SearchKey::Unanswered.to_imap_string(), "UNANSWERED");
        assert_eq!(SearchKey::Undeleted.to_imap_string(), "UNDELETED");
        assert_eq!(SearchKey::Undraft.to_imap_string(), "UNDRAFT");
        assert_eq!(SearchKey::Unflagged.to_imap_string(), "UNFLAGGED");
        assert_eq!(SearchKey::Unseen.to_imap_string(), "UNSEEN");
    }

    #[test]
    fn test_logical_operators() {
        let and = SearchKey::And(vec![
            SearchKey::From("alice".into()),
            SearchKey::Subject("hello".into()),
        ]);
        assert_eq!(and.to_imap_string(), "FROM \"alice\" SUBJECT \"hello\"");

        let or = SearchKey::Or(Box::new(SearchKey::Seen), Box::new(SearchKey::Recent));
        assert_eq!(or.to_imap_string(), "OR (SEEN) (RECENT)");

        let not = SearchKey::Not(Box::new(SearchKey::Deleted));
        assert_eq!(not.to_imap_string(), "NOT (DELETED)");
    }

    #[test]
    fn test_search_query_builder() {
        let q = SearchQuery::subject("Security Alert");
        assert_eq!(q.build(), "SUBJECT \"Security Alert\"");

        let q = SearchQuery::from("alerts@arlo.com");
        assert_eq!(q.build(), "FROM \"alerts@arlo.com\"");

        let q = SearchQuery::to("user@example.com");
        assert_eq!(q.build(), "TO \"user@example.com\"");
    }
}
