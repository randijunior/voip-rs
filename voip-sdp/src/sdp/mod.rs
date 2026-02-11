use crate::error::Error;

pub type Uri = String;

pub type SessionName = String;

pub type SessionInformation = String;

pub type EmailAddress = String;

pub type PhoneNumber = String;

#[derive(Default)]
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
    // a=* (zero or more session attribute lines)
    pub attributes: Vec<SdpAttribute>,
    // Time description
    pub time: Vec<TimeDescription>,
    //  Media description, if present
    pub media: Vec<MediaDescription>,
}


impl SessionDescription {
    pub fn set_origin(&mut self, origin: Origin) {
        self.origin = origin;
    }

    pub fn set_name(&mut self, session_name: SessionName) {
        self.session_name = session_name;
    }

    pub fn set_information(&mut self, info: SessionInformation) {
        if let Some(media) = self.last_media_desc_mut() {
            media.title = Some(info);
        } else {
            self.set_information(info);
        }
    }

    pub fn set_email_addr(&mut self, email: EmailAddress) {
        self.email_address = Some(email);
    }

    pub fn set_uri(&mut self, uri: Uri) {
        self.uri = Some(uri);
    }

    pub fn set_attr(&mut self, attr: SdpAttribute) {
        if let Some(media) = self.last_media_desc_mut() {
            media.attributes.push(attr);
        } else {
            self.set_attr(attr);
        }
    }

    pub fn set_bandwidth_information(&mut self, bandwidth: BandwidthInformation) {
        self.bandwidth_information.push(bandwidth);
    }

    pub fn set_media_description(&mut self, media: MediaDescription) {
        self.media.push(media);
    }

    pub fn last_media_desc_mut(&mut self) -> Option<&mut MediaDescription> {
        self.media.last_mut()
    }

    fn last_time_desc_mut(&mut self) -> Option<&mut TimeDescription> {
        self.time.last_mut()
    }

    pub fn set_time_desc(&mut self, time: TimeDescription) {
        self.time.push(time);
    }
    pub fn set_repeat_times(&mut self, time: RepeatTimes) -> Result<(), Error> {
        if let Some(timing) = self.last_time_desc_mut() {
            timing.repeat_times.push(time);
            Ok(())
        } else {
            return Err(Error::SdpTimeDescriptionNotFound);
        }
    }
    pub fn set_phone(&mut self, phone: PhoneNumber) {
        self.phone_number = Some(phone);
    }
    pub fn set_connection(&mut self, conn: ConnectionInformation) {
        self.connection_information = Some(conn);
    }
}


pub struct TimeDescription {
    // t=  (time the session is active)
    pub time_active: TimeActive,

    // r=* (zero or more repeat times)
    // r=<repeat interval> <active duration> <offsets from start-time>
    pub repeat_times: Vec<RepeatTimes>

    // z=* (optional time zone offset line)
}

pub struct RepeatTimes {
    pub repeat_interval: i64,
    pub active_duration: i64,
    pub offsets: Vec<i64>,
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

pub enum Bwtype {
    CT,
    AS,
    RR,
    RS,
    TIAS,
    Other(String),
}
pub struct BandwidthInformation {
    pub bwtype: Bwtype,
    pub bandwidth: u64,
}

pub struct SdpAttribute {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Default)]
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

pub enum SdpTransport {
    UDP,
    RTPAVP,
    RTPSAVP,
    RTPSAVPF,
}


pub struct MediaDescription {
    // m=  (media name and transport address)
    // m=<media> <port>/<number of ports> <proto> <fmt>
    pub media: MediaType,
    pub protocol: SdpTransport,
    pub port: u16,
    pub number_of_ports: Option<usize>,
    pub media_formats: Vec<String>,
    // i=* (media title)
    pub title: Option<String>,
    // c=* (connection information -- optional if included at session level)
    pub connection_info: Option<ConnectionInformation>,
    // b=* (zero or more bandwidth information lines)
    pub bandwidth_information: Vec<BandwidthInformation>,
    // a=* (zero or more media attribute lines)
    pub attributes: Vec<SdpAttribute>,
}
