#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    pub imap4rev1: bool,
    pub imap4rev2: bool,
    pub condstore: bool,
    pub qresync: bool,
    pub move_ext: bool,
    pub uidplus: bool,
    pub idle: bool,
}

impl Capabilities {
    pub fn parse(response: &str) -> Self {
        let mut caps = Capabilities::default();
        let upper = response.to_uppercase();

        if upper.contains("IMAP4REV1") {
            caps.imap4rev1 = true;
        }
        if upper.contains("IMAP4REV2") {
            caps.imap4rev2 = true;
        }
        if upper.contains("CONDSTORE") {
            caps.condstore = true;
        }
        if upper.contains("QRESYNC") {
            caps.qresync = true;
        }
        if upper.contains("MOVE") {
            caps.move_ext = true;
        }
        if upper.contains("UIDPLUS") {
            caps.uidplus = true;
        }
        if upper.contains("IDLE") {
            caps.idle = true;
        }

        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gmail_caps() {
        let cap_str = "* CAPABILITY IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST MOVE CONDSTORE ENABLE UTF8=ACCEPT";
        let caps = Capabilities::parse(cap_str);
        assert!(caps.imap4rev1);
        assert!(!caps.imap4rev2);
        assert!(caps.move_ext);
        assert!(caps.condstore);
        assert!(caps.idle);
    }

    #[test]
    fn test_parse_rev2_caps() {
        let cap_str = "* CAPABILITY IMAP4rev2 MOVE UIDPLUS";
        let caps = Capabilities::parse(cap_str);
        assert!(caps.imap4rev2);
        assert!(caps.move_ext);
        assert!(caps.uidplus);
    }
}
