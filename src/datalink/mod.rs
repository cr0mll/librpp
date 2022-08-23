
use regex::Regex;

pub mod ethernet;
// pub use ethernet::EthernetLayer;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MACAddr {
    addr: [u8; 6]
}

const MAC_REGEX: &str = r"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$";

impl MACAddr {
    pub fn new(addr: [u8; 6]) -> Self {
        MACAddr { addr: addr }
    }

    /// Takes a string in the form of XX:XX:XX:XX:XX:XX and produces a MAC address.
    pub fn from_str(str: &str) -> Self {
        let re = Regex::new(MAC_REGEX).unwrap();
        if !re.is_match(str) { panic!("Specified string is not a valid MAC address!"); }

        let bytes = hex::decode(str.replace(':', "")).unwrap();
        
        MACAddr { addr: bytes.try_into().unwrap() }
    }

    /// Returns a reference to the bytes of the MAC address.
    pub fn get(&self) -> &[u8; 6] {
        &self.addr
    }

    /// Sets the MAC address to the given bytes.
    pub fn set(&mut self, bytes: [u8; 6]) {
        self.addr = bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::MACAddr;

    #[test]
    fn test_mac_addr() {
        let mut mac = MACAddr::new([0x23, 0xAC, 0x12, 0, 0xAF, 0]);
        assert_eq!(mac, MACAddr::from_str("23:AC:12:00:AF:00"));

        mac.set(*MACAddr::from_str("aa:ab:ac:ad:ae:af").get());
        assert_eq!(mac, MACAddr::from_str("aa:ab:ac:ad:ae:af"));
    }
}