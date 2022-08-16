use std::mem::size_of;

use byteorder::{ByteOrder, NetworkEndian};

use crate::Raw;

/// Flag masks for the flags field of DNSHeader.
mod flags {
    pub const QUERY: u16 = 0b1000_0000_0000_0000;
    pub const OPCODE: u16 = 0b0111_1000_0000_0000;
    pub const AUTHORITATIVE: u16 = 0b0000_0100_0000_0000;
    pub const TRUNCATED: u16 = 0b0000_0010_0000_0000;
    pub const RECURSION_DESIRED: u16 = 0b0000_0001_0000_0000;
    pub const RECURSION_AVAILABLE: u16 = 0b0000_0000_1000_0000;
    pub const AUTHENTIC_DATA: u16 = 0b0000_0000_0010_0000;
    pub const CHECKING_DISABLED: u16 = 0b0000_0000_0001_0000;
    pub const RESERVED: u16 = 0b0000_0000_0100_0000;
    pub const RCODE: u16 = 0b0000_0000_0000_1111;
}

/// A structure representing a DNS header.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub questions_count: u16,
    pub answers_count: u16,
    pub name_servers_count: u16,
    pub additional_records_count: u16
}

impl DNSHeader {
    /// Constructs an empty DNS header
    pub fn new() -> Self {
        DNSHeader { id: 0, flags: 0, questions_count: 0, answers_count: 0, name_servers_count: 0, additional_records_count: 0 }
    }

    /// Constructs a DNS header from the values given.
    /// Use this when artificially creating packets.
    pub fn from_values(id: u16, flags: u16, questions_count: u16, answers_count: u16, name_servers_count: u16, additional_records_count: u16) -> Self {
        DNSHeader { id, flags, questions_count, answers_count, name_servers_count, additional_records_count }
    }

    /// Parses an array of bytes into a DNS header.
    /// The size of the header is fixed, so we can use size_of::<u16>() * 6 to calculate it - a total of 12 bytes.
    pub fn from_bytes(bytes: [u8; size_of::<u16>() * 6]) -> Self {
        DNSHeader { 
            id: NetworkEndian::read_u16(&bytes[0..2]),
            flags: NetworkEndian::read_u16(&bytes[2..4]),
            questions_count: NetworkEndian::read_u16(&bytes[4..6]),
            answers_count: NetworkEndian::read_u16(&bytes[6..8]),
            name_servers_count: NetworkEndian::read_u16(&bytes[8..10]),
            additional_records_count: NetworkEndian::read_u16(&bytes[10..])
        }
    }

    /// Checks the header flags to see if the DNS packet is a query or response packet.
    /// If the flag is set to 0, then this is a query.
    /// If the flag is set to 1, then this is a response.
    pub fn is_query(&self) -> bool {
        self.flags & flags::QUERY == 0 // 0 - query, 1 - response
    }

    /// Retrieves the DNS opcode from the flags field.
    pub fn get_opcode(&self) -> OpCode {
        ((self.flags & flags::OPCODE) >> flags::OPCODE.trailing_zeros()).into()
    }

    /// Returns whether or not the packet is an authoritative answer.
    pub fn is_authoritative_answer(&self) -> bool {
        self.flags & flags::AUTHORITATIVE != 0
    }

    /// Returns whether or not the packet is truncated.
    pub fn is_truncated(&self) -> bool {
        self.flags & flags::TRUNCATED != 0
    }

    /// Returns whether or not recursion is desired.
    pub fn is_recursion_desired(&self) -> bool {
        self.flags & flags::RECURSION_DESIRED != 0
    }

    /// Returns whether or not recursion is available.
    pub fn is_recursion_available(&self) -> bool {
        self.flags & flags::RECURSION_AVAILABLE != 0
    }

    /// Returns the response code which the DNS server issued.
    pub fn get_response_code(&self) -> RCode {
        (self.flags & flags::RCODE).into()
    }

}

impl Raw for DNSHeader {
    fn raw(&self) -> Vec<u8> {
        let mut bytes:Vec<u8> = vec![0; self.raw_size()];

        NetworkEndian::write_u16(&mut bytes[0..2], self.id);
        NetworkEndian::write_u16(&mut bytes[2..4], self.flags);
        NetworkEndian::write_u16(&mut bytes[4..6], self.questions_count);
        NetworkEndian::write_u16(&mut bytes[6..8], self.answers_count);
        NetworkEndian::write_u16(&mut bytes[8..10], self.name_servers_count);
        NetworkEndian::write_u16(&mut bytes[10..12], self.additional_records_count);

        bytes
    }

    fn raw_size(&self) -> usize {
        size_of::<u16>() * 6
    }
}

/// An enum representing the possible values for the DNS opcode.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum OpCode {
    /// Normal query
    StandardQuery = 0,
    /// Inverse query (query a name by IP)
    InverseQuery = 1,
    /// Server status request
    ServerStatusRequest = 2,
    /// Notify query
    Notify = 4,
    /// Update query [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136)
    Update = 5,
    /// Reserved opcode for future use
    Reserved,
}

impl From<u16> for OpCode {
    fn from(code: u16) -> Self {
        use OpCode::*;
        match code {
            0 => StandardQuery,
            1 => InverseQuery,
            2 => ServerStatusRequest,
            4 => Notify,
            5 => Update,
            _ => Reserved,
        }
    }
}

/// An enum representing the possible values for the response code in the packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RCode {
    /// No error condition
    NoError = 0,
    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,
    /// Server failure - The name server was unable to process this query due to a problem with the name server.
    ServerFailure = 2,
    /// Name Error - Meaningful only for responses from an authoritative name server,  
    /// this code signifies that the domain name referenced in the query does not exist.
    NameError = 3,
    /// Not Implemented - The name server does not support the requested kind of query.
    NotImplemented = 4,
    /// Refused - The name server refuses to perform the specified operation for policy reasons.  
    /// For example, a name server may not wish to provide the information to the particular requester,   
    /// or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
    Refused = 5,
    /// Some name that ought not to exist, does exist.
    /// [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136)
    YXDOMAIN = 6,
    /// Some RRset that ought not to exist, does exist.
    /// [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136)
    YXRRSET = 7,
    /// Some RRset that ought to exist, does not exist.
    /// [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136)
    NXRRSET = 8,
    /// The server is not authoritative for the zone named in the Zone Section.
    /// [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136)
    NOTAUTH = 9,
    /// A name used in the Prerequisite or Update Section is not within the zone denoted by the Zone Section.
    /// [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136)
    NOTZONE = 10,

    /// Reserved for future use.
    Reserved,
}

impl From<u16> for RCode {
    fn from(code: u16) -> Self {
        use RCode::*;
        match code {
            0 => NoError,
            1 => FormatError,
            2 => ServerFailure,
            3 => NameError,
            4 => NotImplemented,
            5 => Refused,
            6 => YXDOMAIN,
            7 => YXRRSET,
            8 => NXRRSET,
            9 => NOTAUTH,
            10 => NOTZONE,
            _ => RCode::Reserved,
        }
    }
}