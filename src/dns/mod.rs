mod dns_header;
mod question;
mod resource_record;

pub use dns_header::*;
pub use question::*;
pub use resource_record::*;


pub struct DnsPacket {
    header: DnsHeader,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>
}
