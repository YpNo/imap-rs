/// Represents a search criterion in an IMAP SEARCH command.
#[derive(Debug, Clone)]
pub enum SearchKey {
    From(String),
    To(String),
    Subject(String),
    Body(String),
    Text(String),
    All,
    Answered,
    Deleted,
    Draft,
    Flagged,
    Recent,
    Seen,
    Unanswered,
    Undeleted,
    Undraft,
    Unflagged,
    Unseen,
    And(Vec<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    Not(Box<SearchKey>),
}

impl SearchKey {
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

pub struct SearchQuery {
    key: SearchKey,
}

impl SearchQuery {
    pub fn new(key: SearchKey) -> Self {
        Self { key }
    }

    pub fn from(addr: &str) -> Self {
        Self::new(SearchKey::From(addr.to_string()))
    }

    pub fn to(addr: &str) -> Self {
        Self::new(SearchKey::To(addr.to_string()))
    }

    pub fn subject(text: &str) -> Self {
        Self::new(SearchKey::Subject(text.to_string()))
    }

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
        assert_eq!(SearchKey::From("alice".into()).to_imap_string(), "FROM \"alice\"");
        assert_eq!(SearchKey::To("bob".into()).to_imap_string(), "TO \"bob\"");
        assert_eq!(SearchKey::Subject("hello".into()).to_imap_string(), "SUBJECT \"hello\"");
        assert_eq!(SearchKey::Body("world".into()).to_imap_string(), "BODY \"world\"");
        assert_eq!(SearchKey::Text("foo".into()).to_imap_string(), "TEXT \"foo\"");
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

        let or = SearchKey::Or(
            Box::new(SearchKey::Seen),
            Box::new(SearchKey::Recent),
        );
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
