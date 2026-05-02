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
