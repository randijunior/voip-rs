use utils::{Scanner, is_newline, is_not_newline, is_space};

use crate::error::{ParseSdpError, Result};
use crate::sdp::{
    AddrType, ConnectionInformation, MediaDescription, MediaType, NetType, Origin, SdpMessage,
    TransportProtocol,
};

const PROTOCOL_VERSION: u8 = b'v';
const ORIGIN: u8 = b'o';
const SESSION_NAME: u8 = b's';
const URI: u8 = b'u';
const EMAIL_ADDRESS: u8 = b'e';
const PHONE_NUMBER: u8 = b'p';
const CONNECTION_INFORMATION: u8 = b'c';
const BANDWIDTH_INFORMATION: u8 = b'b';

const TIME_ACTIVE: u8 = b't';
const REPEAT_TIME: u8 = b'r';
const TIME_ZONE_OFFSET: u8 = b'z';

const MEDIA_DESCRIPTION: u8 = b'm';

const SDP_ATTRIBUTE: u8 = b'a';

type SdpField = u8;

#[derive(Debug, PartialEq, Eq, Clone)]
enum State {
    INIT,
    SESSION,
    MEDIA,
}

struct SdpParser<'buf> {
    scanner: Scanner<'buf>,
    state: State,
}

impl<'buf> SdpParser<'buf> {
    #[inline]
    pub fn new<B>(buf: &'buf B) -> Self
    where
        B: AsRef<[u8]> + ?Sized,
    {
        Self {
            scanner: Scanner::new(buf.as_ref()),
            state: State::INIT,
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
                // Session Atribute
                SDP_ATTRIBUTE if self.state == State::SESSION => {}
                // Media Atribute
                SDP_ATTRIBUTE if self.state == State::MEDIA => {}
                PROTOCOL_VERSION => {
                    self.parse_version()?;
                }
                ORIGIN => {
                    self.state = State::SESSION;
                    let origin = self.parse_origin()?;
                    builder.set_origin(origin);
                }
                SESSION_NAME => {
                    let name = self.read_str()?;
                    builder.set_session_name(name);
                }
                CONNECTION_INFORMATION => {}
                // SESSION_INFORMATION
                b'i' if self.state == State::SESSION => {
                    let name = self.read_str()?;
                    builder.set_session_information(name);
                }
                // MEDIA_TITLE
                b'i' if self.state == State::MEDIA => {}
                URI => {
                    let uri = self.read_str()?;
                    builder.set_session_uri(uri);
                }
                EMAIL_ADDRESS => {
                    let email = self.read_str()?;
                    builder.set_session_email_addr(email);
                }
                PHONE_NUMBER => {}
                BANDWIDTH_INFORMATION => {}

                TIME_ACTIVE => {}
                REPEAT_TIME => {}
                TIME_ZONE_OFFSET => {}

                MEDIA_DESCRIPTION => {
                    if self.state != State::MEDIA {
                        self.state = State::MEDIA;
                    }
                    let media = self.parse_media_description()?;

                    builder.set_media_description(media);
                }
                _ => (),
            }
            self.scanner.read_while(is_newline);
        }

        todo!()
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
        let user = self.read_str()?;
        self.handle_ws();
        let session_id = self.scanner.read_u16()?;
        self.handle_ws();
        let session_version = self.scanner.read_u16()?;
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
        let bytes = self.scanner.read_while(|b| !is_space(b));
        let mediatype = match bytes {
            b"audio" => MediaType::Audio,
            b"video" => MediaType::Video,
            _other => {
                todo!()
            }
        };
        self.scanner.advance_by(bytes.len());

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
        self.scanner.advance_by(bytes.len());

        todo!()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_sdp() {
        let example_sdp = "v=0
      o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1
      s=Call to John Smith
      i=SDP Offer #1
      u=http://www.jdoe.example.com/home.html
      e=Jane Doe <jane@jdoe.example.com>
      p=+1 617 555-6011
      c=IN IP4 198.51.100.1
      t=0 0
      m=audio 49170 RTP/AVP 0
      m=audio 49180 RTP/AVP 0
      m=video 51372 RTP/AVP 99
      c=IN IP6 2001:db8::2
      a=rtpmap:99 h263-1998/90000";
    }
}
