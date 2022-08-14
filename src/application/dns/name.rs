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
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.contents)
    }
}

/// A DNS resource name comprised of labels
#[derive(Debug)]
pub struct Name {
    labels: Vec<Label>
}

impl Name {

    fn new(s: &str) -> Name {
        // DNS names usually have 2-3 labels: example.com, other.example.com
        let mut labels: Vec<Label> = Vec::with_capacity(3);
        for l in s.split('.') {
            labels.push(Label::new(l.to_string()));
        }

        Name { labels }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut labels: Vec<Label> = Vec::new();

        let mut i = 0;
        while i < bytes.len() {
            let contents = String::from_utf8_lossy(&bytes[i + 1..i + bytes[i] as usize + 1]).to_owned();
            labels.push(Label::new(contents.to_string()));
            i += bytes[i] as usize + 1;
        }

        Name { labels }
    }

    fn from_labels(labels: Vec<Label>) -> Self {
        Name { labels }
    }

    fn labels(&self) -> &Vec<Label> {
        &self.labels
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
    use crate::application::Name;
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
        println!("{:?}", name.labels())
    }
}