
pub struct DnsHeader {
    id: u16,
    query: bool,
    opcode: OpCode,
    authoritative_answer: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: RCode,
    questions_count: u16,
    answers_count: u16,
    name_servers_count: u16,
    additional_records_count: u16
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