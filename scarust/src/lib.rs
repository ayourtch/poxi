use std::any::Any;
use std::any::TypeId;
use std::fmt;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::ops::Div;

#[derive(Clone)]
pub struct LayerStack {
    pub layers: Vec<Box<dyn Layer>>,
}

impl fmt::Debug for LayerStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.layers.iter()).finish()
    }
}

impl<T: Layer> Div<T> for LayerStack {
    type Output = LayerStack;
    fn div(mut self, rhs: T) -> Self::Output {
        self.layers.push(rhs.embox());
        self
    }
}

impl Div<LayerStack> for LayerStack {
    type Output = LayerStack;
    fn div(mut self, rhs: LayerStack) -> Self::Output {
        for x in rhs.layers {
            self.layers.push(x);
        }
        self
    }
}

pub trait Layer: Debug + Any {
    fn embox(self) -> Box<dyn Layer>;
    fn box_clone(&self) -> Box<dyn Layer>;
    fn to_stack(self) -> LayerStack
    where
        Self: Sized,
    {
        LayerStack {
            layers: vec![self.embox()],
        }
    }
    fn type_id_is(&self, x: TypeId) -> bool {
        self.type_id() == x
    }
}

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Box<dyn Layer> {
        self.box_clone()
    }
}

/*
impl <'a> PartialEq for LayerStack<'a> {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}

impl <'a> Eq for LayerStack<'a> {
}
*/

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Udp {
    pub sport: u16,
    pub dport: u16,
    pub len: Option<u16>,
    pub chksum: Option<u16>,
}

impl Layer for Udp {
    fn embox(self) -> Box<dyn Layer> {
        Box::new(self)
    }
    fn box_clone(&self) -> Box<dyn Layer> {
        Box::new((*self).clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IpFlags {
    // FIXME
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpOption {
    NOP(),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ip {
    pub version: u8,
    pub ihl: Option<u8>,
    pub tos: u8,
    pub len: Option<u16>,
    pub id: u16,
    pub flags: IpFlags,
    pub frag: u16,
    pub ttl: u8,
    pub proto: u8,
    pub chksum: Option<u16>,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub options: Vec<IpOption>,
}

impl Default for Ip {
    fn default() -> Self {
        Ip {
            version: 4,
            ihl: None,
            tos: 0,
            len: None,
            id: 1,
            flags: Default::default(),
            frag: 0,
            ttl: 64,
            proto: 0, // hopopt
            chksum: None,
            src: Ipv4Addr::new(127, 0, 0, 1),
            dst: Ipv4Addr::new(127, 0, 0, 1),
            options: vec![],
        }
    }
}

impl<T: Layer> Div<T> for Ip {
    type Output = LayerStack;
    fn div(mut self, rhs: T) -> Self::Output {
        let mut out = LayerStack {
            layers: vec![self.embox()],
        };
        out.layers.push(rhs.embox());
        out
    }
}

impl Layer for Ip {
    fn embox(self) -> Box<dyn Layer> {
        Box::new(self)
    }
    fn box_clone(&self) -> Box<dyn Layer> {
        Box::new((*self).clone())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        use crate::Ip;
        let ip = Ip {
            ..Default::default()
        };
        eprintln!("{:?}", ip);
        assert_eq!(2 + 2, 4);
    }
}
