use std::mem::size_of;

use byteorder::{NetworkEndian, ByteOrder};

use crate::{application::dns::Name, Raw};


/// Represents an AFSDB record. AFSDB records pertain to servers with ASD cells.
#[derive(Debug)]
pub struct AFSDB {
    pub subtype: u16,
    pub name: Name
}

impl AFSDB {
    fn new(subtype: u16, name: Name) -> Self {
        AFSDB { subtype, name }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        AFSDB {
            subtype: NetworkEndian::read_u16(bytes),
            name: Name::from_bytes(&bytes[2..])
        }
    }
}

impl Raw for AFSDB {
    fn raw(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.raw_size());

        bytes.push(0);
        bytes.push(0);

        NetworkEndian::write_u16(&mut bytes, self.subtype);
        bytes.append(&mut self.name.raw());

        bytes
    }

    fn raw_size(&self) -> usize {
        size_of::<u16>() + self.name.raw_size()
    }
}