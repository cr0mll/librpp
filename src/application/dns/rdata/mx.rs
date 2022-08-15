use std::mem::size_of;

use byteorder::{NetworkEndian, ByteOrder};

use crate::{application::dns::Name, Raw};


/// Used for mail exchange information
#[derive(Debug)]
pub struct MX {
    /// An integer which specifies the preference given to this record among others with the same owner.  
    /// Lower values mean higher preference.
    pub preference: u16,

    /// Specifies a host to act as a mail exchange.
    pub host: Name
}

impl MX {
    pub fn new(preference: u16, host: Name) -> Self {
        MX { preference, host }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        MX {
            preference: NetworkEndian::read_u16(bytes),
            host: Name::from_bytes(&bytes[2..])
        }
    }
}

impl Raw for MX {
    fn raw(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.raw_size());

        bytes.push(0);
        bytes.push(0);

        NetworkEndian::write_u16(&mut bytes, self.preference);
        bytes.append(&mut self.host.raw());

        bytes
    }

    fn raw_size(&self) -> usize {
        size_of::<u16>() + self.host.raw_size()
    }
}