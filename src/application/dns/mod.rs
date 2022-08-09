mod dns_header;
mod question;
mod resource_record;

pub use dns_header::*;
pub use question::*;
pub use resource_record::*;

use crate::packet::{Layer, LayerType};

pub struct DnsLayer {
    header: DnsHeader,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>
}

impl Layer for DnsLayer {
    fn get_name(&self) -> &'static str {
        "DNS"
    }

    fn get_type(&self) -> LayerType {
        LayerType::DNSLayer
    }

    fn get_OSI_level(&self) -> u8 {
        7
    }
}

pub struct Label {
    length: u8,
    contents: String
}

impl Label {
    fn new(length: u8, contents: String) -> Self {
        Label { length, contents }
    }
}

/// A DNS resource name comprised of labels
pub struct Name {
    labels: Vec<Label>
}

impl Name {
    fn new(bytes: &[u8]) -> Self {
        let mut labels: Vec<Label> = Vec::new();

        let mut i = 0;
        while bytes[i] != 0 {
            let contents = String::from_utf8_lossy(&bytes[i..i + bytes[i] as usize]).to_owned();
            labels.push(Label::new(bytes[i], contents.to_string()));
            i += bytes[i] as usize + 1;
        }

        Name { labels }
    }
}

/// Possible Type values for a Question in a DNS packet  
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Type {
    /// Represents an IPv4 address
    A,
    /// Represents an IPv6 address. [RFC 3596](https://tools.ietf.org/html/rfc3596)
    AAAA,
    /// For servers with ASD cells
    AFSDB,
    /// Used to acquire general information about a host.  
    /// The main use is for protocols such as FTP that can use special procedures
    /// when talking between machines or operating systems of the same type.
    HINFO,
    /// An ISDN (Integrated Service Digital Network) - a telephone number
    ISDN,
    ///  For xpressing location information. [RFC 1876](https://datatracker.ietf.org/doc/html/rfc1876)
    LOC,
    /// Used to acquire mailbox or mail list information.
    MINFO,
    /// MX is used to acquire mail exchange information
    MX,
    /// NSAP structure [RFC 1706](https://datatracker.ietf.org/doc/html/rfc1706)
    NSAP,
    /// Used to represent arbitrary data.
    NULL,
    /// Route-through binding for hosts that do not have their own direct wide area network addresses
    RT,
    /// RP Responsible Person [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-2.2)
    RP,
    /// Start of zone authority.
    SOA,
    /// Specifies the location of the server(s) for a specific protocol and domain.
    SRV,
    /// A text record.
    TXT,
    /// Used to describe the well known services supported by a particular protocol on a particular internet address.
    WKS,
    /// A request for incremental transfer of a zone. [RFC 1995](https://tools.ietf.org/html/rfc1995)
    IXFR,
    /// A request for a transfer of an entire zone, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    AXFR,
    /// A request for mailbox-related records (MB, MG or MR), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MAILB,
    /// A request for mail agent RRs (Obsolete - see MX), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MAILA,
    /// A request for all records, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    ANY,
}


/// Possible Class values for a Resource in a DNS packet  
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Class {
    /// The Internet, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    IN = 1,
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CS = 2,
    /// The CHAOS class, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CH = 3,
    /// Hesiod [Dyer 87], [RFC 1035](https://tools.ietf.org/html/rfc1035)
    HS = 4,
    /// [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136)
    NONE = 254,
}