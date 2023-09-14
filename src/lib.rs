use std::any::Any;
use std::any::TypeId;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::ops::Div;
use std::str::FromStr;
#[macro_use]
extern crate scarust_derive;

pub trait FromStringHashmap<T>: Default {
    fn from_string_hashmap(hm: HashMap<String, String>) -> T;
}

pub trait IntoIpv4Addr {
    fn into_ipv4addr(self) -> std::net::Ipv4Addr;
}

impl IntoIpv4Addr for &str {
    fn into_ipv4addr(self) -> std::net::Ipv4Addr {
        self.parse().expect("Invalid IP address format")
    }
}

impl IntoIpv4Addr for [u8; 4] {
    fn into_ipv4addr(self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(self[0], self[1], self[2], self[3])
    }
}

fn parse_pair<T>(v: &str) -> T
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => val,
        Err(_) => panic!("unable to parse"),
    }
}

fn parse_pair_as_option<T>(v: &str) -> Option<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => Some(val),
        Err(_) => panic!("unable to parse"),
    }
}

fn parse_pair_as_vec<T>(v: &str) -> Vec<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => vec![val],
        Err(_) => panic!("unable to parse"),
    }
}

#[derive(FromStringHashmap, Default)]
pub struct FunnyTest {
    pub foo: u32,
    pub bar: Option<u32>,
}

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

pub trait New {
    fn new() -> Self
    where
        Self: Default;
}

impl<T: Default> New for T {
    fn new() -> Self {
        Self::default()
    }
}

pub trait Layer: Debug + Any + New {
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

use std::num::ParseIntError;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IpFlags {
    // FIXME
}

impl FromStr for IpFlags {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpFlags {})
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpOption {
    NOP(),
}

impl FromStr for IpOption {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpOption::NOP())
    }
}

#[derive(FromStringHashmap, Clone, Debug, Eq, PartialEq)]
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

impl Ip {
    pub fn version(&mut self, version: u8) -> Self {
        let mut ip = self.clone();
        ip.version = version;
        ip
    }
    pub fn id(&mut self, id: u16) -> Self {
        let mut ip = self.clone();
        ip.id = id;
        ip
    }
    pub fn src<T_Ipv4Addr: IntoIpv4Addr>(&mut self, src: T_Ipv4Addr) -> Self {
        let src = src.into_ipv4addr();
        let mut ip = self.clone();
        ip.src = src;
        ip
    }
    pub fn dst<T_Ipv4Addr: IntoIpv4Addr>(&mut self, dst: T_Ipv4Addr) -> Self {
        let dst = dst.into_ipv4addr();
        let mut ip = self.clone();
        ip.dst = dst;
        ip
    }
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
        let mut out = self.to_stack();
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
