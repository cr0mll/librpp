
mod flags {
    pub const QUERY: u16 = 0b1000_0000_0000_0000;
    pub const OPCODE_MASK: u16 = 0b0111_1000_0000_0000;
    pub const AUTHORITATIVE: u16 = 0b0000_0100_0000_0000;
    pub const TRUNCATED: u16 = 0b0000_0010_0000_0000;
    pub const RECURSION_DESIRED: u16 = 0b0000_0001_0000_0000;
    pub const RECURSION_AVAILABLE: u16 = 0b0000_0000_1000_0000;
    pub const AUTHENTIC_DATA: u16 = 0b0000_0000_0010_0000;
    pub const CHECKING_DISABLED: u16 = 0b0000_0000_0001_0000;
    pub const RESERVED_MASK: u16 = 0b0000_0000_0100_0000;
    pub const RESPONSE_CODE_MASK: u16 = 0b0000_0000_0000_1111;
}

pub struct DnsHeader {
    pub id: u16,
    flags: u16,
    pub questions_count: u16,
    pub answers_count: u16,
    pub name_servers_count: u16,
    pub additional_records_count: u16
}



impl DnsHeader {
    fn is_query(&self) -> bool {
        self.flags & flags::QUERY == 0 // 0 - query, 1 - response
    }

    fn get_opcode(&self) -> OpCode {
        ((self.flags & flags::OPCODE_MASK) >> flags::OPCODE_MASK.trailing_zeros()).into()
    }

    fn is_authoritative_answer(&self) -> bool {
        self.flags & flags::AUTHORITATIVE != 0
    }

    fn is_truncated(&self) -> bool {
        self.flags & flags::TRUNCATED != 0
    }

    fn is_recursion_desired(&self) -> bool {
        self.flags & flags::RECURSION_DESIRED != 0
    }

    fn is_recursion_available(&self) -> bool {
        self.flags & flags::RECURSION_AVAILABLE != 0
    }

    fn get_response_code(&self) -> RCode {
        (self.flags & flags::RESPONSE_CODE_MASK).into()
    }

}

#[derive(Debug, Copy, Clone, PartialEq)]
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

#[derive(Debug, Copy, Clone, PartialEq)]
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