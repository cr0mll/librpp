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
            if l.get_osi_level() == layer.get_osi_level() {
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
    fn get_osi_level(&self) -> u8;
    fn get_payload(&self) -> Vec<u8>;

    fn as_any(&self) -> &dyn Any;
}

/// A private enum for the implementation of Packet.
/// The Packet struct automatically converts to the underlying layer type when get_layer() is invoked.
enum Layers {
    DNSLayer(application::dns::DNSLayer)
}


pub enum LayerType {
    DNSLayer
}

impl From<Layers> for LayerType {
    fn from(other: Layers) -> Self {
        match other {
            // Layers::EthernetLayer(_) => Self::EthernetLayer,
            Layers::DNSLayer(_) => Self::DNSLayer
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::application::dns::DNSLayer;

    #[test]
    fn test_layer() {
        use crate::Packet;
        
        let mut packet = Packet::new();

        
    }
}