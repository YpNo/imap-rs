#[derive(Debug, PartialEq, Eq)]
pub enum Response<'a> {
    Status(StatusResponse<'a>),
    Data(DataResponse<'a>),
    Continue(ContinueReq<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct StatusResponse<'a> {
    pub tag: Option<&'a str>, // None means untagged '*'
    pub status: Status,
    pub code: Option<ResponseCode<'a>>,
    pub text: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    No,
    Bad,
    PreAuth,
    Bye,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseCode<'a> {
    Alert,
    BadCharset(&'a [&'a str]),
    Capability(Vec<&'a str>),
    Parse,
    PermanentFlags(Vec<&'a str>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
    Other(&'a str, Option<&'a str>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DataResponse<'a> {
    Capability(Vec<&'a str>),
    List {
        flags: Vec<&'a str>,
        delimiter: Option<&'a str>,
        name: &'a str,
    },
    Lsub {
        flags: Vec<&'a str>,
        delimiter: Option<&'a str>,
        name: &'a str,
    },
    Status {
        mailbox: &'a str,
        items: Vec<StatusItem>,
    },
    Search(Vec<u32>),
    Flags(Vec<&'a str>),
    Exists(u32),
    Recent(u32),
    Expunge(u32),
    Fetch {
        seq: u32,
        attributes: Vec<FetchAttribute<'a>>,
    },
    Other(Vec<&'a [u8]>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StatusItem {
    Messages(u32),
    Recent(u32),
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub enum FetchAttribute<'a> {
    Flags(Vec<&'a str>),
    InternalDate(&'a str),
    Rfc822Size(u32),
    Envelope(&'a [u8]),
    Body(&'a [u8]),
    BodyStructure(&'a [u8]),
    BodySection {
        section: Option<&'a str>,
        data: Option<&'a [u8]>,
    },
    Uid(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ContinueReq<'a> {
    pub code: Option<ResponseCode<'a>>,
    pub text: &'a str,
}
