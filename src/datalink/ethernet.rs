use crate::packet::{Layer, LayerType};

pub struct EthernetLayer {

}

impl Layer for EthernetLayer {
    fn get_name(&self) -> &'static str {
        "Ethernet"
    }

    fn get_type(&self) -> LayerType {
        LayerType::EthernetLayer
    }

    fn get_OSI_level(&self) -> u8 {
        2
    }
}