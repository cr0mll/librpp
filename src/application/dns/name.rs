use crate::Raw;

#[derive(Debug)]
pub struct Label {
    /// DNS name labels may be at most 255 in length.
    length: u8, 
    contents: String
}

impl Label {
    fn new(contents: String) -> Self {
        Label { length: u8::try_from(contents.len()).expect("DNS name labels may be at most 255 in length."), contents }
    }

    fn from_bytes(bytes: &[u8]) -> Self {

        if bytes.len() < 2 { panic!("Insufficient bytes to create DNS name label!"); }

        Label { 
            length: bytes[0], 
            contents: String::from_utf8_lossy(&bytes[1..]).to_string() 
        }
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.contents)
    }
}

impl Raw for Label {
    fn raw(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.raw_size());

        bytes.push(self.length);
        bytes.extend_from_slice(self.contents.as_bytes());

        bytes
    }

    fn raw_size(&self) -> usize {
        // Just the raw string's size plus one byte for its length
        usize::from(self.length) + 1
    }
}

/// A DNS resource name comprised of labels.
#[derive(Debug)]
pub struct Name {
    labels: Vec<Label>
}

impl Name {
    /// Constructs a DNS resource name from a string.
    pub fn new(s: &str) -> Name {
        // DNS names usually have 2-3 labels: example.com, other.example.com
        let mut labels: Vec<Label> = Vec::with_capacity(3);
        for l in s.split('.') {
            labels.push(Label::new(l.to_string()));
        }

        Name { labels }
    }

    /// Constructs a DNS resource name from the given bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut labels: Vec<Label> = Vec::new();

        let mut i = 0;

        while i < bytes.len() && bytes[i] != 0{
            let contents = String::from_utf8_lossy(&bytes[i + 1..i + bytes[i] as usize + 1]).to_owned();
            labels.push(Label::new(contents.to_string()));
            i += bytes[i] as usize + 1;
        }

        Name { labels }
    }

    /// Constructs a DNS resource name from the given labels.
    pub fn from_labels(labels: Vec<Label>) -> Self {
        Name { labels }
    }

    /// Returns a reference to the labels of the DNS resource name.
    pub fn labels(&self) -> &Vec<Label> {
        &self.labels
    }

    /// Returns the length of the DNS name as a string including the "." separators.
    pub fn str_len(&self) -> usize {
        let mut length: usize = 0;
        for label in &self.labels {
            length += usize::from(label.length) + 1; // +1 for the separator after each label.
        }

        length - 1 // -1 because the last label does not actually have a separator following it.
    }
}

impl Raw for Name {
    fn raw(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.raw_size());

        
        for label in &self.labels {
            bytes.append(&mut label.raw());
        }

        bytes.push(0);
        bytes
    }

    fn raw_size(&self) -> usize {
        let mut size = 0;
        for label in &self.labels {
            size += label.raw_size();
        }

        size + 1 // + 1 for the null byte at the end.
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.labels[0].to_string())?;

        if self.labels.len() > 1 {
            for label in &self.labels[1..] {
                write!(f, ".{}", label)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Raw;
    use crate::application::dns::Name;
    use crate::application::dns::name;

    #[test]
    fn test_dns_name() {
        std::env::set_var("RUST_BACKTRACE", "1");
        // Name creation
        let name = Name::new("from.string.example.com");
        assert_eq!(name.to_string(), "from.string.example.com");

        let name = Name::from_bytes(b"\x05other\x07example\x03com");
        assert_eq!(name.to_string(), "other.example.com");

        let labels: Vec<name::Label> = vec![name::Label::new("new".to_string()), name::Label::new("example".to_string()), name::Label::new("com".to_string())];
        let name = Name::from_labels(labels);
        assert_eq!(name.to_string(), "new.example.com");

        // Name get labels
        println!("Label names: {:?}", name.labels());

        // Name and Label raw
        let label = name::Label::new("from".to_string());
        println!("Label raw: {:?}", label.raw());

        let name = Name::new("from.string.example.com");
        println!("Name raw: {:?}", name.raw());
    }
}