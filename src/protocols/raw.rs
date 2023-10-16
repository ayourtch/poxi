use crate::*;

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(decode_suppress)]
pub struct raw {
    pub data: Vec<u8>,
}

impl Layer for String {
    fn embox(self) -> Box<dyn Layer> {
        Box::new(self)
    }
    fn box_clone(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }
    fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack) {
        out_stack.layers.push(Box::new(self.clone()))
    }
    fn encode(
        &self,
        stack: &LayerStack,
        my_index: usize,
        encoded_layers: &EncodingVecVec,
    ) -> Vec<u8> {
        self.as_bytes().to_owned()
    }
}
