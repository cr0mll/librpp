pub mod datalink;
pub mod application;
pub mod packet;

pub use packet::Packet;

pub trait Raw {
    fn raw(&self) -> Vec<u8>;
    fn raw_size(&self) -> usize;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
