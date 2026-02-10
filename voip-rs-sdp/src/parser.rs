use utils::{Scanner, is_newline, is_not_newline, is_space, lookup_table};

use crate::error::{ParseSdpError, Result};
use crate::sdp::*;

type SdpField = u8;

const PROTOCOL_VERSION: SdpField = b'v';
const ORIGIN: SdpField = b'o';
const SESSION_NAME: SdpField = b's';
const URI: SdpField = b'u';
const EMAIL_ADDRESS: SdpField = b'e';
const PHONE_NUMBER: SdpField = b'p';
const CONNECTION_INFORMATION: SdpField = b'c';
const BANDWIDTH_INFORMATION: SdpField = b'b';

const TIME_ACTIVE: SdpField = b't';
const REPEAT_TIME: SdpField = b'r';
const TIME_ZONE_OFFSET: SdpField = b'z';

const MEDIA_DESCRIPTION: SdpField = b'm';

const SDP_ATTRIBUTE: SdpField = b'a';

const TOKEN: &[u8] = b"!#$%&'*+-.^_`{|}~";

const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

lookup_table!(TOKEN_TAB => ALPHANUMERIC, TOKEN);


struct SdpParser<'buf> {
    scanner: Scanner<'buf>,
}

impl<'buf> SdpParser<'buf> {
    #[inline]
    pub fn new<B>(buf: &'buf B) -> Self
    where
        B: AsRef<[u8]> + ?Sized,
    {
        Self {
            scanner: Scanner::new(buf.as_ref()),
        }
    }

    pub fn parse<B>(buf: &'buf B) -> Result<SdpMessage>
    where
        B: AsRef<[u8]> + ?Sized,
    {
        Self::new(buf).parse_sdp()
    }

    pub fn parse_sdp(&mut self) -> Result<SdpMessage> {
        let mut builder = SdpMessage::builder();

        while !self.is_eof() {
            match self.read_field()? {
                SDP_ATTRIBUTE => {
                    let attr = self.parse_attribute()?;

                    if let Some(media) = builder.last_media_desc_mut() {
                        media.attributes.push(attr);
                    } else {
                        builder.set_session_attr(attr);
                    }
                }
                PROTOCOL_VERSION => {
                    self.parse_version()?;
                }
                ORIGIN => {
                    let origin = self.parse_origin()?;
                    builder.set_origin(origin);
                }
                SESSION_NAME => {
                    let name = self.read_str()?;
                    builder.set_session_name(name);
                }
                CONNECTION_INFORMATION => {
                    let conn = self.parse_connection_info()?;
                    builder.set_session_connection(conn);
                }
                b'i' => {
                    let name = self.read_str()?;
                    if let Some(media) = builder.last_media_desc_mut() {
                        media.title = Some(name);
                    } else {
                        builder.set_session_information(name);
                    }
                }

                URI => {
                    let uri = self.read_str()?;
                    builder.set_session_uri(uri);
                }
                EMAIL_ADDRESS => {
                    let email = self.read_str()?;
                    builder.set_session_email_addr(email);
                }
                PHONE_NUMBER => {
                    let phone = self.read_str()?;

                    builder.set_session_phone(phone);
                }
                BANDWIDTH_INFORMATION => {}

                TIME_ACTIVE => {
                    let timing = self.parse_time()?;
                    builder.set_time_desc(timing);
                }
                REPEAT_TIME => {}
                TIME_ZONE_OFFSET => {}

                MEDIA_DESCRIPTION => {
                    let media = self.parse_media_description()?;

                    builder.set_media_description(media);
                }
                _ => (),
            }
            self.scanner.read_while(is_newline);
        }

        builder.build()
    }

    fn parse_version(&mut self) -> Result<()> {
        self.scanner
            .must_read(b'0')
            .map_err(|_| ParseSdpError::SdpInvalidProtocolVersion)?;

        Ok(())
    }

    #[inline]
    fn handle_ws(&mut self) {
        self.scanner.read_while(is_space);
    }

    fn parse_origin(&mut self) -> Result<Origin> {
        let user = self
            .scanner
            .read_while_as_str(|b| !b.is_ascii_whitespace())?
            .to_owned();
        self.handle_ws();
        let session_id = self.scanner.read_u64()?;
        self.handle_ws();
        let session_version = self.scanner.read_u64()?;
        self.handle_ws();
        let nettype = self.read_str()?;
        self.handle_ws();
        let addrtype = self.read_str()?;
        self.handle_ws();
        let unicast_address = self.read_str()?;

        Ok(Origin {
            user,
            session_id,
            session_version,
            nettype,
            addrtype,
            unicast_address,
        })
    }

    fn parse_connection_info(&mut self) -> Result<ConnectionInformation> {
        let nettype = if self.scanner.matches_prefix(b"IN") {
            self.scanner.advance_by(2);
            NetType::IN
        } else {
            let other_type = self.scanner.read_while_as_str(|b| !is_space(b))?;
            NetType::Other(other_type.to_owned())
        };

        self.handle_ws();

        let addrtype = match self.scanner.peek_bytes(3) {
            Some(b"IP4") => AddrType::IP4,
            Some(b"IP6") => AddrType::IP6,
            _ => {
                return Err(ParseSdpError::SyntaxError {
                    s: "Invalid Addr Type".to_owned(),
                    pos: *self.scanner.position(),
                }
                .into());
            }
        };
        self.scanner.advance_by(3);

        self.handle_ws();
        let conection_address = self.read_str()?;
        self.handle_ws();

        Ok(ConnectionInformation {
            nettype,
            addrtype,
            conection_address,
        })
    }

    fn parse_media_description(&mut self) -> Result<MediaDescription> {
        let bytes = self.read_token();
        let media = match bytes {
            "audio" => MediaType::Audio,
            "video" => MediaType::Video,
            _other => {
                todo!()
            }
        };
        self.handle_ws();
        let port = self.scanner.read_u16()?;
        self.handle_ws();

        let bytes = self.scanner.read_while(|b| !is_space(b));

        let proto = match bytes {
            b"UDP" | b"udp" => TransportProtocol::UDP,
            b"RTP/AVP" => TransportProtocol::RTPAVP,
            b"RTP/SAVP" => TransportProtocol::RTPSAVP,
            b"RTP/SAVPF" => TransportProtocol::RTPSAVPF,
            _ => {
                return Err(ParseSdpError::SyntaxError {
                    s: "Invalid Transport Protocol".to_owned(),
                    pos: *self.scanner.position(),
                }
                .into());
            }
        };

        let mut media_formats = vec![];

        while self.scanner.next_byte_if(is_space).is_some() {
            let fmt = self.read_token();

            media_formats.push(fmt.to_owned());

            if matches!(self.scanner.peek_byte(), Some(b'\r') | Some(b'\n') | None) {
                break;
            }
        }

        Ok(MediaDescription {
            media,
            port,
            number_of_ports: None,
            proto,
            media_formats,
            title: None,
            connection_info: None,
            bandwidth_information: vec![],
            attributes: vec![],
        })
    }

    fn parse_time(&mut self) -> Result<TimeDescription> {
        let start_at = self.scanner.read_u64()?;

        self.scanner.must_read(b' ')?;

        let stop_at = self.scanner.read_u64()?;

        Ok(TimeDescription {
            time_active: TimeActive { start_at, stop_at },
            repeat_times: vec![],
        })
    }

    fn parse_attribute(&mut self) -> Result<Attribute> {
        let attr_name = self.read_token().to_owned();

        let attr_value = if self.scanner.advance_if_eq(b':').is_some() {
            let str = self.scanner.read_while_as_str(is_not_newline)?;
            Some(str.to_owned())
        } else {
            None
        };

        Ok(Attribute {
            name: attr_name,
            value: attr_value,
        })
    }

    #[inline]
    fn read_token(&mut self) -> &str {
        unsafe { self.scanner.read_while_as_str_unchecked(is_token) }
    }

    #[inline]
    fn read_str(&mut self) -> Result<String> {
        let attr = self.scanner.read_while_as_str(is_not_newline)?;
        Ok(attr.to_owned())
    }

    fn read_field(&mut self) -> Result<SdpField> {
        let field = self.scanner.next()?;

        self.scanner.must_read(b'=')?;

        Ok(field)
    }

    fn is_eof(&self) -> bool {
        self.scanner.is_eof()
    }
}

#[inline(always)]
pub(crate) fn is_token(b: u8) -> bool {
    TOKEN_TAB[b as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_sdp() {
        let example_sdp = concat! {
            "v=0\r\n",
            "o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1\r\n",
            "s=Call to John Smith\r\n",
            "i=SDP Offer #1\r\n",
            "u=http://www.jdoe.example.com/home.html\r\n",
            "e=Jane Doe <jane@jdoe.example.com>\r\n",
            "p=+1 617 555-6011\r\n",
            "c=IN IP4 198.51.100.1\r\n",
            "t=0 0\r\n",
            "m=audio 49170 RTP/AVP 0\r\n",
            "m=audio 49180 RTP/AVP 0\r\n",
            "m=video 51372 RTP/AVP 99\r\n",
            "c=IN IP6 2001:db8::2\r\n",
            "a=rtpmap:99 h263-1998/90000\r\n"
        };

        SdpParser::parse(example_sdp).unwrap();
    }
}
