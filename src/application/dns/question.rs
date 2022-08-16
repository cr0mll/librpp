
use core::panic;
use std::mem::size_of;

use byteorder::{NetworkEndian, ByteOrder};

use crate::application::dns::{Name, Type, Class};
use crate::Raw;

/// A structure representing a DNS query.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Question {
    pub name: Name,
    pub qtype: Type,
    class: u16,
}

impl Question {
    /// Constructs a DNS question from the given values.
    pub fn new(name: Name, qtype: Type, class: Class, unicast_response: bool) -> Self {
        Question {
            name,
            qtype,
            // Sets the upper-most bit of class to 1, if unicast_response is true
            class: class as u16 | (0x8000 * unicast_response as u16)
        }
    }

    /// Constructs a DNS question from the given bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let name = Name::from_bytes(bytes);
        let name_end = name.raw_size();
        
        Question {
            name,
            qtype: Type::try_from(NetworkEndian::read_u16(&bytes[name_end..name_end + 2])).expect("DNS question has invalid type"),
            class: NetworkEndian::read_u16(&bytes[name_end + 2..name_end + 4])
        }
    }

    /// Retreives the class of the question.
    /// # Panics
    /// If the class is invalid, which may only happen if the question has been manually altered without using the provided API.
    pub fn class(&self) -> Class {
        // Apparently Rust has no API for converting ints to enums. C++ - 1, Rust - 0.
        Class::try_from(self.class & 0x00ff).expect("DNS question contains invalid classs!")
    }

    /// Returns whether or not the question prefers a unicast response.
    /// This information is extracted from the class field.
    pub fn prefers_unicast_response(&self) -> bool {
        self.class & 0x8000 != 0
    }
}

impl Raw for Question {
    fn raw(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.raw_size());

        let mut name = self.name.raw();
        let name_size = name.len();
        bytes.append(&mut name);

        // Reserve size for type and class
        bytes.push(0);
        bytes.push(0);
        bytes.push(0);
        bytes.push(0);

        // Write type and class
        NetworkEndian::write_u16(&mut bytes[name_size..name_size + size_of::<u16>()], self.qtype as u16);
        NetworkEndian::write_u16(&mut bytes[name_size + size_of::<u16>()..name_size + 2 * size_of::<u16>()], self.class as u16);

        bytes
    }

    fn raw_size(&self) -> usize {
        self.name.raw_size() + size_of::<Type>() + size_of::<Class>()
    }
}

impl std::fmt::Debug for Question {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Question")
         .field("name", &self.name)
         .field("type", &self.qtype)
         .field("class", &self.class())
         .field("prefers unicast response", &self.prefers_unicast_response())
         .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{application::dns::{name::Name, Type, Class}, Raw};

    use super::Question;

    #[test]
    fn test_dns_question() {
        std::env::set_var("RUST_BACKTRACE", "1");

        let q = Question::new(Name::new("question.example.com"), Type::A, Class::IN, true);

        assert_eq!(q.class(), Class::IN);
        assert_eq!(q.prefers_unicast_response(), true);

        let q1 = Question::from_bytes(&q.raw());
        assert_eq!(q, q1);
        assert_eq!(q.raw(), q1.raw());

    }
}