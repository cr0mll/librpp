use std::mem::size_of;

use byteorder::{NetworkEndian, ByteOrder};

use crate::Raw;

use crate::application::dns::{Type,Class, Name};
use super::rdata::RData;

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: Name,
    pub rtype: Type,
    pub class: Class,
    pub ttl: u16,
    pub rlength: u16,
    pub rdata: RData
}

impl ResourceRecord {
    pub fn new(name: Name, rtype: Type, class: Class, ttl: u16, rlength: u16, rdata: RData) -> Self {
        ResourceRecord { name, rtype, class, ttl, rlength, rdata }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let name = Name::from_bytes(bytes);
        let start = name.raw_size();

        let rtype = Type::try_from(NetworkEndian::read_u16(&bytes[start..start + 2])).unwrap();

        ResourceRecord {
            name,
            rtype,
            class: Class::try_from(NetworkEndian::read_u16(&bytes[start + 2..start + 4])).unwrap(),
            ttl: NetworkEndian::read_u16(&bytes[start + 4..start + 6]),
            rlength: NetworkEndian::read_u16(&bytes[start + 6..start + 8]),
            rdata: RData::from_bytes(rtype, &bytes[start + 8..])
        }

    }
}

impl Raw for ResourceRecord {
    fn raw(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.raw_size());

        bytes.append(&mut self.name.raw());

        let mut start = self.name.raw_size();

        bytes.push(0);
        bytes.push(0);
        NetworkEndian::write_u16(&mut bytes[start..start + 2], self.rtype as u16);
        start += 2;

        bytes.push(0);
        bytes.push(0);
        NetworkEndian::write_u16(&mut bytes[start..start + 2], self.class as u16);
        start += 2;

        bytes.push(0);
        bytes.push(0);
        NetworkEndian::write_u16(&mut bytes[start..start + 2], self.ttl as u16);
        start += 2;

        bytes.push(0);
        bytes.push(0);
        NetworkEndian::write_u16(&mut bytes[start..start + 4], self.rlength as u16);
        start += 2;

        bytes.append(&mut self.rdata.raw());

        bytes
    }

    fn raw_size(&self) -> usize {
        self.name.raw_size() + size_of::<Type>() + size_of::<Class>() + size_of::<u16>() + size_of::<u16>() + self.rdata.raw_size()
    }
}
