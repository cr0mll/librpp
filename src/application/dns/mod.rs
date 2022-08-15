mod header;
mod question;
mod resource_record;
mod name;

use std::mem::size_of;

pub use header::*;
use num_enum::TryFromPrimitive;
pub use question::*;
pub use resource_record::*;
pub use name::Name;

use crate::packet::{Layer, LayerType};
use crate::Raw;

pub struct DNSLayer {
    header: DNSHeader,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>
}

impl DNSLayer {
    
}

impl Layer for DNSLayer {
    fn get_name(&self) -> &'static str {
        "DNS"
    }

    fn get_type(&self) -> LayerType {
        LayerType::DNSLayer
    }

    fn get_osi_level(&self) -> u8 {
        7
    }

    fn as_any(&self) -> &dyn std::any::Any { self }

    fn get_payload(&self) -> Vec<u8> {
        let mut bytes:Vec<u8> = Vec::with_capacity(self.raw_size() - size_of::<DNSHeader>());

        for q in &self.questions {
            bytes.append(&mut q.raw());
        }
        for rr in &self.answers {
            bytes.append(&mut rr.raw());
        }
        for auth in &self.authority {
            bytes.append(&mut auth.raw());
        }
        for add in &self.additional {
            bytes.append(&mut add.raw());
        }

        bytes
    }
}

impl Raw for DNSLayer {
    fn raw(&self) -> Vec<u8> {
        let mut bytes:Vec<u8> = Vec::with_capacity(self.raw_size());

        bytes.append(&mut self.header.raw()); // header
        bytes.append(&mut self.get_payload()); // payload

        bytes
    }

    fn raw_size(&self) -> usize {
        let mut size = size_of::<DNSHeader>();

        for q in &self.questions {
            size += q.raw_size();
        }
        for rr in &self.answers {
            size += rr.raw_size();
        }
        for auth in &self.authority {
            size += auth.raw_size();
        }
        for add in &self.additional {
            size += add.raw_size();
        }

        size
    }
}

/// Possible Type values for a Question in a DNS packet  
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, TryFromPrimitive)]
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, TryFromPrimitive)]
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
