mod header;
mod question;
mod resource_record;
mod name;
mod rdata;

use std::mem::size_of;

pub use header::*;
use num_enum::TryFromPrimitive;
pub use question::*;
pub use resource_record::*;
pub use name::Name;

use crate::packet::{Layer, LayerType};
use crate::Raw;

#[derive(Debug)]
pub struct DNSLayer {
    header: DNSHeader,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>
}

impl DNSLayer {
    pub fn new(header: DNSHeader, questions: Vec<Question>, answers: Vec<ResourceRecord>, authority: Vec<ResourceRecord>, additional: Vec<ResourceRecord>) -> Self{
        DNSLayer {
            header,
            questions,
            answers,
            authority,
            additional
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let header = DNSHeader::from_bytes(bytes[0..size_of::<DNSHeader>()].try_into().unwrap());

        let mut questions: Vec<Question> = Vec::with_capacity(header.questions_count as usize);
        let mut answers: Vec<ResourceRecord> = Vec::with_capacity(header.answers_count as usize);
        let mut authority: Vec<ResourceRecord> = Vec::with_capacity(header.name_servers_count as usize);
        let mut additional: Vec<ResourceRecord> = Vec::with_capacity(header.additional_records_count as usize);

        let mut start: usize = header.raw_size();
        
        for i in 0..header.questions_count {
            let q = Question::from_bytes(&bytes[start..]);
            start += q.raw_size();
            questions.push(q);
        }

        for i in 0..header.answers_count {
            let a = ResourceRecord::from_bytes(&bytes[start..]);
            start += a.raw_size();
            answers.push(a);
        }

        for i in 0..header.name_servers_count {
            let auth = ResourceRecord::from_bytes(&bytes[start..]);
            start += auth.raw_size();
            authority.push(auth);
        }

        for i in 0..header.additional_records_count {
            let add = ResourceRecord::from_bytes(&bytes[start..]);
            start += add.raw_size();
            additional.push(add);
        }

        DNSLayer { header, questions, answers, authority, additional }
    }
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
    A = 0x0001,
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

#[cfg(test)]
mod tests {
    use crate::{Raw, application::dns::DNSHeader};

    use super::DNSLayer;


    #[test]
    fn test_dns_name() {
        std::env::set_var("RUST_BACKTRACE", "full");

        let bytes = b"\x42\x74\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x70\x72\x6f\x64\x0e\x69\x6e\x67\x65\x73\x74\x69\x6f\x6e\x2d\x65\x64\x67\x65\x04\x70\x72\x6f\x64\x07\x64\x61\x74\x61\x6f\x70\x73\x06\x6d\x6f\x7a\x67\x63\x70\x03\x6e\x65\x74\x00\x00\x01\x00\x01";
        let layer = DNSLayer::from_bytes(bytes);
        println!("DNS layer: {:#?}", layer);

        let new_bytes = layer.raw();
        assert_eq!(new_bytes, bytes);
        
        let layer = DNSLayer::from_bytes(&new_bytes);
        println!("DNS layer: {:#?}", layer);
    }
}