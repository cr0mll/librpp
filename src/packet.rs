use crate::{datalink, application};

use std::any::Any;

pub const MAX_LAYER_COUNT: u8 = 7;

pub struct Packet {
    layers: Vec<Box<dyn Layer>>
}

impl Packet {
    fn new() -> Self {
        Packet { layers: Vec::with_capacity(7) }
    }

    /// If the layer is present in the packet, then it is safe do downcast the trait object into the underlying type
    fn get_layer(&self, name: &str) -> Option<&Box<dyn Layer>> {
        for layer in &self.layers {
            if layer.get_name() == name {
                return Some(layer);
            }
        }

        None
    }

    fn add_layer(&mut self, layer: Box<dyn Layer>) -> Result<(), Box<dyn std::error::Error>> {
        for l in &self.layers {
            if l.get_OSI_level() == layer.get_OSI_level() {
                return Result::Err(Box::new(DuplicateLayerError {}));
            }
        }

        self.layers.push(layer);
        return Ok(());
    }
}

#[derive(Debug, Clone)]
struct DuplicateLayerError;

impl std::error::Error for DuplicateLayerError {}

impl std::fmt::Display for DuplicateLayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Layer already exists!")
    }
}

pub trait Layer {
    fn get_name(&self) -> &'static str;
    fn get_type(&self) -> LayerType;
    fn get_OSI_level(&self) -> u8;
    fn as_any(&self) -> &dyn Any;
}

/// A private enum for the implementation of Packet.
/// The Packet struct automatically converts to the underlying layer type when get_layer() is invoked.
enum Layers {
    EthernetLayer(datalink::EthernetLayer),
    DNSLayer(application::DnsLayer)
}


pub enum LayerType {
    EthernetLayer,
    DNSLayer
}

impl From<Layers> for LayerType {
    fn from(other: Layers) -> Self {
        match other {
            Layers::EthernetLayer(_) => Self::EthernetLayer,
            Layers::DNSLayer(_) => Self::DNSLayer
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::application::DnsLayer;

    #[test]
    fn test_layer() {
        use crate::Packet;
        use crate::datalink::EthernetLayer;
        
        let mut packet = Packet::new();

        match packet.add_layer(Box::new(EthernetLayer {mac: String::from("1213")})) {
            Ok(_) => println!("Layer added!"),
            Err(e) => panic!("{}", e)
        }

        match packet.get_layer("Ethernet") {
            Some(layer) => {
                if let Some(layer) = layer.as_any().downcast_ref::<EthernetLayer>() {
                    println!("Layer mac: {}", layer.mac);
                }
            },
            None => panic!("Layer not found")
        }
    }
}