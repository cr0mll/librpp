// use crate::packet::{Layer, LayerType};

// pub struct EthernetLayer {
//     pub mac: String
// }

// impl Layer for EthernetLayer {
//     fn get_name(&self) -> &'static str {
//         "Ethernet"
//     }

//     fn get_type(&self) -> LayerType {
//         LayerType::EthernetLayer
//     }

//     fn get_osi_level(&self) -> u8 {
//         2
//     }

//     fn as_any(&self) -> &dyn std::any::Any { self }
// }