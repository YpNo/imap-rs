use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    Seen,
    Answered,
    Flagged,
    Deleted,
    Draft,
    Recent,
    Custom(String),
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Flag::Seen => write!(f, "\\Seen"),
            Flag::Answered => write!(f, "\\Answered"),
            Flag::Flagged => write!(f, "\\Flagged"),
            Flag::Deleted => write!(f, "\\Deleted"),
            Flag::Draft => write!(f, "\\Draft"),
            Flag::Recent => write!(f, "\\Recent"),
            Flag::Custom(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreAction {
    Add,
    Remove,
    Set,
}

impl StoreAction {
    pub fn to_imap_prefix(&self, silent: bool) -> &str {
        match self {
            StoreAction::Add => {
                if silent {
                    "+FLAGS.SILENT"
                } else {
                    "+FLAGS"
                }
            }
            StoreAction::Remove => {
                if silent {
                    "-FLAGS.SILENT"
                } else {
                    "-FLAGS"
                }
            }
            StoreAction::Set => {
                if silent {
                    "FLAGS.SILENT"
                } else {
                    "FLAGS"
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_display() {
        assert_eq!(Flag::Seen.to_string(), "\\Seen");
        assert_eq!(Flag::Answered.to_string(), "\\Answered");
        assert_eq!(Flag::Flagged.to_string(), "\\Flagged");
        assert_eq!(Flag::Deleted.to_string(), "\\Deleted");
        assert_eq!(Flag::Draft.to_string(), "\\Draft");
        assert_eq!(Flag::Recent.to_string(), "\\Recent");
        assert_eq!(Flag::Custom("MyFlag".into()).to_string(), "MyFlag");
    }

    #[test]
    fn test_store_action_prefix() {
        assert_eq!(StoreAction::Add.to_imap_prefix(false), "+FLAGS");
        assert_eq!(StoreAction::Add.to_imap_prefix(true), "+FLAGS.SILENT");
        assert_eq!(StoreAction::Remove.to_imap_prefix(false), "-FLAGS");
        assert_eq!(StoreAction::Remove.to_imap_prefix(true), "-FLAGS.SILENT");
        assert_eq!(StoreAction::Set.to_imap_prefix(false), "FLAGS");
        assert_eq!(StoreAction::Set.to_imap_prefix(true), "FLAGS.SILENT");
    }
}
