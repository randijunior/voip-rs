use crate::error::Error;

pub type Uri = String;

pub type SessionName = String;

pub type SessionInformation = String;

pub type EmailAddress = String;

pub type PhoneNumber = String;

pub struct SdpMessage {
    pub session: SessionDescription,
    pub time: TimeDescription,
    pub media: Vec<MediaDescription>,
}

impl SdpMessage {
    pub fn builder() -> Builder {
        Builder::default()
    }
}

#[derive(Default)]
pub struct Builder {
    origin: Option<Origin>,
    session_name: Option<SessionName>,
    session_information: Option<SessionInformation>,
    session_uri: Option<Uri>,
    session_email_address: Option<EmailAddress>,
    session_attributes: Vec<Attribute>,
    session_phone: Option<PhoneNumber>,
    session_connection: Option<ConnectionInformation>,
    session_bandwidth: Vec<BandwidthInformation>,
    session_timing: Option<TimeDescription>,
    media: Vec<MediaDescription>,
}

impl Builder {
    pub fn set_origin(&mut self, origin: Origin) {
        self.origin = Some(origin);
    }

    pub fn set_session_name(&mut self, session_name: SessionName) {
        self.session_name = Some(session_name);
    }

    pub fn set_session_information(&mut self, session_info: SessionInformation) {
        self.session_information = Some(session_info);
    }

    pub fn set_session_email_addr(&mut self, email: EmailAddress) {
        self.session_email_address = Some(email);
    }

    pub fn set_session_uri(&mut self, uri: Uri) {
        self.session_uri = Some(uri);
    }

    pub fn set_session_attr(&mut self, session_attr: Attribute) {
        self.session_attributes.push(session_attr);
    }

    pub fn set_media_description(&mut self, media: MediaDescription) {
        self.media.push(media);
    }

    pub fn last_media_desc_mut(&mut self) -> Option<&mut MediaDescription> {
        self.media.last_mut()
    }

    pub fn set_time_desc(&mut self, time: TimeDescription) {
        self.session_timing = Some(time);
    }
    pub fn set_session_phone(&mut self, phone: PhoneNumber) {
        self.session_phone = Some(phone);
    }
    pub fn set_session_connection(&mut self, conn: ConnectionInformation) {
        self.session_connection = Some(conn);
    }

    pub fn build(self) -> Result<SdpMessage, Error> {
        Ok(SdpMessage { session: SessionDescription {
            origin: self.origin.unwrap(),
            session_name: self.session_name.unwrap(),
            session_information: self.session_information,
            uri: self.session_uri,
            email_address: self.session_email_address,
            phone_number: self.session_phone,
            connection_information: self.session_connection,
            bandwidth_information: self.session_bandwidth,
            attributes: self.session_attributes,
        }, time: self.session_timing.unwrap(), media: self.media })
    }
}

pub struct SessionDescription {
    // v=  (protocol version)
    // o=  (originator and session identifier)
    pub origin: Origin,
    // s=  (session name)
    pub session_name: SessionName,
    // i=* (session information)
    pub session_information: Option<SessionInformation>,
    // u=* (URI of description)
    pub uri: Option<Uri>,
    // e=* (email address)
    pub email_address: Option<EmailAddress>,

    // p=* (phone number)
    pub phone_number: Option<PhoneNumber>,

    // c=* (connection information)
    pub connection_information: Option<ConnectionInformation>,

    // b=* (zero or more bandwidth information lines)
    pub bandwidth_information: Vec<BandwidthInformation>,

    // k=* (obsolete)
    // a=* (zero or more session attribute lines)
    pub attributes: Vec<Attribute>,
}

pub struct TimeDescription {
    // t=  (time the session is active)
    pub time_active: TimeActive,

    // r=* (zero or more repeat times)
    pub repeat_times: Vec<RepeatTime>, // z=* (optional time zone offset line)
}

pub struct RepeatTime {
    repeat_interval: i64,
    active_duration: i64,
    offsets: Vec<i64>,
}

pub enum AddrType {
    IP4,
    IP6,
}

pub enum NetType {
    IN,
    Other(String),
}

pub struct ConnectionInformation {
    pub nettype: NetType,
    pub addrtype: AddrType,
    pub conection_address: String,
}

pub struct TimeActive {
    pub start_at: u64,
    pub stop_at: u64,
}

enum Bwtype {
    CT,
    AS,
    Other(String),
}
pub struct BandwidthInformation {
    bwtype: Bwtype,
    bandwidth: u64,
}

pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
}

pub struct Origin {
    pub user: String,
    pub session_id: u64,
    pub session_version: u64,
    pub nettype: String,
    pub addrtype: String,
    pub unicast_address: String,
}

pub enum MediaType {
    Audio,
    Video,
    Text,
    Application,
    Message,
}

pub enum TransportProtocol {
    UDP,
    RTPAVP,
    RTPSAVP,
    RTPSAVPF,
}

pub struct MediaDescription {
    pub media: MediaType,
    pub title: Option<String>,
    pub port: u16,
    pub number_of_ports: Option<usize>,
    pub proto: TransportProtocol,
    pub media_formats: Vec<String>,
    pub connection_info: Option<ConnectionInformation>,
    pub bandwidth_information: Vec<BandwidthInformation>,
    pub attributes: Vec<Attribute>,
}
