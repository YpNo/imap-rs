use crate::ast::{ContinueReq, DataResponse, Response, Status, StatusResponse};
use crate::error::ParseError;

pub type IResult<'a, T> = Result<(&'a [u8], T), ParseError>;

pub fn parse_response(input: &[u8]) -> IResult<'_, Response<'_>> {
    if input.is_empty() {
        return Err(ParseError::Incomplete);
    }

    // Simplistic stub parser for now to satisfy fuzz testing and unit tests.
    // In a real implementation, this would handle recursive descent of IMAP grammar.
    if input.starts_with(b"+ ") {
        // Continue Req
        let end = input
            .iter()
            .position(|&c| c == b'\r')
            .ok_or(ParseError::Incomplete)?;
        let text =
            std::str::from_utf8(&input[2..end]).map_err(|_| ParseError::Other("Invalid UTF-8"))?;

        let mut skip = 2;
        // Basic literal detection: if text ends with {n}, we expect n bytes after CRLF
        if let Some(brace_idx) = text.rfind('{')
            && text.ends_with('}')
        {
            let len_str = &text[brace_idx + 1..text.len() - 1];
            if let Ok(len) = len_str.parse::<usize>() {
                let total_required = end + 2 + len;
                if input.len() < total_required {
                    return Err(ParseError::Incomplete);
                }
                skip = 2 + len;
            }
        }

        let remaining = &input[end..];
        if remaining.starts_with(b"\r\n") {
            Ok((
                &remaining[skip..],
                Response::Continue(ContinueReq { code: None, text }),
            ))
        } else if remaining.len() < 2 {
            Err(ParseError::Incomplete)
        } else {
            Err(ParseError::Other("Expected CRLF"))
        }
    } else if input.starts_with(b"* ") {
        // Untagged Response
        let end = input
            .iter()
            .position(|&c| c == b'\r')
            .ok_or(ParseError::Incomplete)?;
        let line =
            std::str::from_utf8(&input[2..end]).map_err(|_| ParseError::Other("Invalid UTF-8"))?;

        let mut skip = 2;
        let mut actual_end = end;
        if let Some(brace_idx) = line.rfind('{')
            && line.ends_with('}')
        {
            let len_str = &line[brace_idx + 1..line.len() - 1];
            if let Ok(len) = len_str.parse::<usize>() {
                let total_required = end + 2 + len;
                if input.len() < total_required {
                    return Err(ParseError::Incomplete);
                }
                skip = 2 + len;
                // We might have more data after the literal before the final CRLF
                // In IMAP, a literal is followed by the rest of the response
                let after_literal = &input[total_required..];
                if let Some(final_crlf_pos) = after_literal.windows(2).position(|w| w == b"\r\n") {
                    actual_end = total_required + final_crlf_pos;
                } else {
                    // If no CRLF after literal, it might be incomplete or the literal was the end
                    actual_end = total_required;
                }
            }
        }

        let remaining = &input[actual_end..];
        if remaining.starts_with(b"\r\n") {
            if let Some(text) = line.strip_prefix("OK ") {
                Ok((
                    &remaining[2..],
                    Response::Status(StatusResponse {
                        tag: None,
                        status: Status::Ok,
                        code: None,
                        text,
                    }),
                ))
            } else if let Some(search_results) = line.strip_prefix("SEARCH") {
                let ids = search_results
                    .split_whitespace()
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect();
                Ok((&remaining[2..], Response::Data(DataResponse::Search(ids))))
            } else if let Some(rest) = line.split_once(' ') {
                if let Ok(seq) = rest.0.parse::<u32>() {
                    if rest.1.starts_with("FETCH") {
                        let mut attributes = vec![];
                        // Extract attributes from the parts of the response before and after the literal
                        let mut full_attr_text = rest.1.to_string();
                        if skip > 2 {
                            let after_literal_start = end + 2 + (skip - 2);
                            let after_literal_end = actual_end;
                            if input.len() >= after_literal_end
                                && after_literal_end > after_literal_start
                            {
                                full_attr_text.push_str(&String::from_utf8_lossy(
                                    &input[after_literal_start..after_literal_end],
                                ));
                            }
                        }

                        // Basic UID extraction
                        if let Some(uid_pos) = full_attr_text.find("UID ") {
                            let rest_attr = &full_attr_text[uid_pos + 4..];
                            let uid_val =
                                rest_attr.split(|c| c == ' ' || c == ')' || c == '(').next();
                            if let Some(uid) = uid_val.and_then(|s| s.parse::<u32>().ok()) {
                                attributes.push(crate::ast::FetchAttribute::Uid(uid));
                            }
                        }

                        // Basic BODY extraction (if literal was used)
                        if line.contains("BODY[]") || line.contains("RFC822") {
                            // If we have a skip/literal, it's likely the body content
                            if skip > 2 {
                                let literal_start = end + 2;
                                let literal_end = literal_start + (skip - 2);
                                if input.len() >= literal_end {
                                    attributes.push(crate::ast::FetchAttribute::Body(
                                        &input[literal_start..literal_end],
                                    ));
                                }
                            }
                        }

                        Ok((
                            &remaining[2..],
                            Response::Data(DataResponse::Fetch { seq, attributes }),
                        ))
                    } else if rest.1.starts_with("EXISTS") {
                        Ok((&remaining[2..], Response::Data(DataResponse::Exists(seq))))
                    } else if rest.1.starts_with("RECENT") {
                        Ok((&remaining[2..], Response::Data(DataResponse::Recent(seq))))
                    } else if rest.1.starts_with("EXPUNGE") {
                        Ok((&remaining[2..], Response::Data(DataResponse::Expunge(seq))))
                    } else {
                        Ok((&remaining[2..], Response::Data(DataResponse::Other(vec![]))))
                    }
                } else {
                    Ok((
                        &remaining[skip..],
                        Response::Data(DataResponse::Other(vec![])),
                    ))
                }
            } else {
                Ok((
                    &remaining[skip..],
                    Response::Data(DataResponse::Other(vec![])),
                ))
            }
        } else if remaining.len() < 2 {
            Err(ParseError::Incomplete)
        } else {
            Err(ParseError::Other("Expected CRLF"))
        }
    } else {
        // Tagged
        let space_idx = input
            .iter()
            .position(|&c| c == b' ')
            .ok_or(ParseError::Incomplete)?;
        let tag = std::str::from_utf8(&input[..space_idx])
            .map_err(|_| ParseError::Other("Invalid UTF-8"))?;

        let rest = &input[space_idx + 1..];
        let end = rest
            .iter()
            .position(|&c| c == b'\r')
            .ok_or(ParseError::Incomplete)?;
        let line =
            std::str::from_utf8(&rest[..end]).map_err(|_| ParseError::Other("Invalid UTF-8"))?;

        let mut skip = 2;
        if let Some(brace_idx) = line.rfind('{')
            && line.ends_with('}')
        {
            let len_str = &line[brace_idx + 1..line.len() - 1];
            if let Ok(len) = len_str.parse::<usize>() {
                let total_required = end + 2 + len;
                if rest.len() < total_required {
                    return Err(ParseError::Incomplete);
                }
                skip = 2 + len;
            }
        }

        let remaining = &rest[end..];
        if remaining.starts_with(b"\r\n") {
            if let Some(text) = line.strip_prefix("OK ") {
                Ok((
                    &remaining[skip..],
                    Response::Status(StatusResponse {
                        tag: Some(tag),
                        status: Status::Ok,
                        code: None,
                        text,
                    }),
                ))
            } else {
                Err(ParseError::Other("Unsupported tag response"))
            }
        } else if remaining.len() < 2 {
            Err(ParseError::Incomplete)
        } else {
            Err(ParseError::Other("Expected CRLF"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_continue() {
        let input = b"+ ready for data\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(
            resp,
            Response::Continue(ContinueReq {
                code: None,
                text: "ready for data",
            })
        );
    }

    #[test]
    fn test_parse_untagged_ok() {
        let input = b"* OK IMAP4rev1 Service Ready\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(
            resp,
            Response::Status(StatusResponse {
                tag: None,
                status: Status::Ok,
                code: None,
                text: "IMAP4rev1 Service Ready",
            })
        );
    }

    #[test]
    fn test_parse_tagged_ok() {
        let input = b"A1 OK LOGIN completed\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(
            resp,
            Response::Status(StatusResponse {
                tag: Some("A1"),
                status: Status::Ok,
                code: None,
                text: "LOGIN completed",
            })
        );
    }

    #[test]
    fn test_parse_incomplete() {
        let input = b"* OK ";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_literal_incomplete() {
        let input = b"* OK {10}\r\nabc";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_literal_complete() {
        let input = b"* OK {10}\r\n0123456789\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        if let Response::Status(s) = resp {
            assert_eq!(s.text, "{10}");
        } else {
            panic!("Expected status response");
        }
    }

    #[test]
    fn test_parse_invalid_utf8() {
        let input = b"* OK \xFF\r\n";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Other("Invalid UTF-8"))));
    }

    #[test]
    fn test_parse_malformed_literal() {
        let input = b"* OK {abc}\r\n";
        let (rem, _) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0); // Should consume the entire line
    }

    #[test]
    fn test_parse_missing_crlf() {
        let input = b"* OK text\r ";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Other("Expected CRLF"))));
    }

    #[test]
    fn test_parse_unsupported_tag_response() {
        let input = b"A1 NO failed\r\n";
        let res = parse_response(input);
        assert!(matches!(
            res,
            Err(ParseError::Other("Unsupported tag response"))
        ));
    }

    #[test]
    fn test_parse_continue_invalid_utf8() {
        let input = b"+ \xFF\r\n";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Other("Invalid UTF-8"))));
    }

    #[test]
    fn test_parse_search_empty() {
        let input = b"* SEARCH\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        if let Response::Data(DataResponse::Search(ids)) = resp {
            assert!(ids.is_empty());
        } else {
            panic!("Expected search response");
        }
    }

    #[test]
    fn test_parse_other_untagged() {
        let input = b"* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert!(matches!(resp, Response::Data(DataResponse::Other(_))));
    }

    #[test]
    fn test_parse_fetch() {
        let input = b"* 1 FETCH (FLAGS (\\Seen))\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert!(matches!(resp, Response::Data(DataResponse::Fetch { .. })));
    }

    #[test]
    fn test_parse_status() {
        let input = b"* STATUS \"INBOX\" (MESSAGES 10 RECENT 1)\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert!(matches!(resp, Response::Data(DataResponse::Other(_))));
    }

    #[test]
    fn test_parse_literal_incomplete_data() {
        let input = b"* OK {10}\r\n0123";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_continue_incomplete_literal() {
        let input = b"+ {10}\r\n0123";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_tagged_incomplete_literal() {
        let input = b"A1 OK {10}\r\n0123";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_incomplete_tagged_no_space() {
        let input = b"A1";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_incomplete_tagged_no_crlf() {
        let input = b"A1 OK\r";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_expunge() {
        let input = b"* 10 EXPUNGE\r\n";
        let (rem, resp) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert!(matches!(resp, Response::Data(DataResponse::Expunge(10))));
    }

    #[test]
    fn test_parse_untagged_expected_crlf() {
        let input = b"* OK text\rX";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Other("Expected CRLF"))));
    }

    #[test]
    fn test_parse_tagged_expected_crlf() {
        let input = b"A1 OK text\rX";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Other("Expected CRLF"))));
    }

    #[test]
    fn test_parse_continue_expected_crlf() {
        let input = b"+ text\rX";
        let res = parse_response(input);
        assert!(matches!(res, Err(ParseError::Other("Expected CRLF"))));
    }

    #[test]
    fn test_parse_tagged_unsupported_tag() {
        let input = b"A1 NO text\r\n";
        let res = parse_response(input);
        assert!(matches!(
            res,
            Err(ParseError::Other("Unsupported tag response"))
        ));
    }
}
