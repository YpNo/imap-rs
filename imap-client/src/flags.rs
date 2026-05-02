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
