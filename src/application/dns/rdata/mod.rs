use std::{net::{Ipv4Addr, Ipv6Addr}, mem::size_of};

use crate::Raw;
use crate::application::dns::Type;
use byteorder::{NetworkEndian, ByteOrder};

mod afsdb;
mod mx;

pub use afsdb::*;
pub use mx::*;

#[derive(Debug)]
/// Similar to dns::Type, but contains data.
pub enum RData {
    /// Represents an IPv4 address
    A(Ipv4Addr),
    /// Represents an IPv6 address. [RFC 3596](https://tools.ietf.org/html/rfc3596)
    AAAA(Ipv6Addr),
    /// For servers with ASD cells
    AFSDB(AFSDB),
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
    MX(MX),
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
    WKS
}

impl RData {
    pub fn from_bytes(rtype: Type, bytes: &[u8]) -> Self {
        match rtype {
            Type::A => RData::A(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            Type::AAAA => { 
                let a = NetworkEndian::read_u16(&bytes[0..2]);
                let b = NetworkEndian::read_u16(&bytes[2..4]);
                let c = NetworkEndian::read_u16(&bytes[4..6]);
                let d = NetworkEndian::read_u16(&bytes[6..8]);
                let e = NetworkEndian::read_u16(&bytes[8..10]);
                let f = NetworkEndian::read_u16(&bytes[10..12]);
                let g = NetworkEndian::read_u16(&bytes[12..14]);
                let h = NetworkEndian::read_u16(&bytes[14..16]);

                RData::AAAA(Ipv6Addr::new(a, b, c, d, e, f, g, h))
            },
            Type::MX => RData::MX(MX::from_bytes(bytes)),
            _ => todo!()
        }
    }
}

impl Raw for RData {
    fn raw(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.raw_size());

        match self {
            RData::A(ip) => {
                bytes.extend([0, 0, 0, 0].iter());
                NetworkEndian::write_u32(&mut bytes, ip.clone().into());
            },
            RData::AAAA(ip) => {
                bytes.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].iter());
                NetworkEndian::write_u128(&mut bytes, ip.clone().into());
            },
            RData::MX(mx) => {
                bytes.append(&mut mx.raw())
            }
            _ => todo!()
        }

        bytes
    }

    fn raw_size(&self) -> usize {
        match self {
            RData::A(_) => size_of::<u32>(),
            RData::AAAA(_) => size_of::<u128>(),
            RData::MX(mx) => mx.raw_size(),
            _ => todo!()
        }
    }
}