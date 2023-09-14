//use std::any::Any;
use std::any::TypeId;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::ops::Div;
use std::ops::Index;
use std::str::FromStr;
#[macro_use]
extern crate mopa;

pub struct ParseNumberError;

macro_rules! INT_TYPE {
    ($TT:ident: $BT:ident) => {
        #[derive(PartialEq, Clone, Eq)]
        pub struct $TT($BT);

        impl std::fmt::Debug for $TT {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&format!("{:?}", &self.0))
            }
        }

        impl Default for $TT {
            fn default() -> Self {
                $TT(0)
            }
        }

        impl $TT {
            pub fn new(val: $BT) -> Self {
                $TT(val)
            }
        }

        impl std::str::FromStr for $TT {
            type Err = ParseNumberError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let res = s.parse();
                if res.is_err() {
                    return Err(ParseNumberError);
                }
                Ok($TT(res.unwrap()))
            }
        }

        impl From<$BT> for $TT {
            fn from(v: $BT) -> Self {
                $TT(v)
            }
        }

        impl From<&str> for $TT {
            fn from(s: &str) -> Self {
                let res = s.parse().unwrap();
                $TT(res)
            }
        }
    };
}

INT_TYPE!(U16: u16);
INT_TYPE!(U32: u32);
INT_TYPE!(U8: u8);

/*
#[derive(PartialEq, Clone, Eq)]
pub struct U16(u16);

impl fmt::Debug for U16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{:?}", &self.0))
    }
}

impl Default for U16 {
    fn default() -> Self {
        U16(0)
    }
}

impl U16 {
    pub fn new(val: u16) -> Self {
        U16(val)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseU16Error;

impl FromStr for U16 {
    type Err = ParseU16Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = s.parse();
        if res.is_err() {
            return Err(ParseU16Error);
        }
        Ok(U16(res.unwrap()))
    }
}

impl From<u16> for U16 {
    fn from(v: u16) -> Self {
        U16(v)
    }
}


impl From<&str> for U16 {
    fn from(s: &str) -> Self {
        let res = s.parse().unwrap();
        U16(res)
    }
}
*/

#[derive(PartialEq, Clone, Eq)]
pub struct Ipv4Address(std::net::Ipv4Addr);

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{:?}", &self.0))
    }
}

impl Default for Ipv4Address {
    fn default() -> Self {
        Ipv4Address(Ipv4Addr::new(0, 0, 0, 0))
    }
}

impl Ipv4Address {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8) -> Self {
        Ipv4Address(Ipv4Addr::new(o1, o2, o3, o4))
    }
}

/*
impl Deref for Ipv4Address {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Ipv4Addr {
        &self.0
    }
}
*/

#[derive(Debug, PartialEq, Eq)]
pub struct ParseIpv4AddressError;

impl FromStr for Ipv4Address {
    type Err = ParseIpv4AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = s.parse();
        if res.is_err() {
            return Err(ParseIpv4AddressError);
        }
        Ok(Ipv4Address(res.unwrap()))
    }
}

impl From<[u8; 4]> for Ipv4Address {
    fn from(arg: [u8; 4]) -> Self {
        Self::new(arg[0], arg[1], arg[2], arg[3])
    }
}

impl From<&str> for Ipv4Address {
    fn from(s: &str) -> Self {
        let res = s.parse().unwrap();
        Ipv4Address(res)
    }
}

#[macro_use]
extern crate scarust_derive;

pub trait FromStringHashmap<T>: Default {
    fn from_string_hashmap(hm: HashMap<String, String>) -> T;
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

impl LayerStack {
    pub fn g<T: Layer>(&self, idx: T) -> &T {
        self[TypeId::of::<T>()].downcast_ref().unwrap()
    }
}

impl Index<TypeId> for LayerStack {
    type Output = Box<dyn Layer>;

    fn index(&self, type_id: TypeId) -> &Self::Output {
        for ref layer in &self.layers {
            if layer.type_id_is(type_id) {
                return layer.clone();
            }
        }
        panic!("Layer not found");
    }
}

impl<T> Index<T> for LayerStack
where
    T: Layer,
{
    type Output = T;
    fn index(&self, typ: T) -> &Self::Output {
        for ref layer in &self.layers {
            if layer.type_id_is(typ.type_id()) {
                return layer.clone().downcast_ref().unwrap();
            }
        }
        panic!("Layer not found");
    }
}

impl Index<&dyn Layer> for LayerStack {
    type Output = Box<dyn Layer>;

    fn index(&self, typ: &dyn Layer) -> &Self::Output {
        for ref layer in &self.layers {
            if layer.type_id_is(typ.type_id()) {
                return layer.clone();
            }
        }
        panic!("Layer not found");
    }
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

pub trait Layer: Debug + mopa::Any + New {
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

mopafy!(Layer);

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

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Default)]
pub struct Udp {
    pub sport: u16,
    pub dport: u16,
    pub len: Option<u16>,
    pub chksum: Option<u16>,
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
    SourceRoute(Vec<Ipv4Address>),
}

impl FromStr for IpOption {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpOption::NOP())
    }
}

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
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
    pub src: Ipv4Address,
    pub dst: Ipv4Address,
    pub options: Vec<IpOption>,
}

impl Ip {
    /*
    pub fn version<T: Into<u8>>(mut self, version: T) -> Self {
        let version = version.into();
        self.version = version;
        self
    }
    pub fn ihl<T: Into<Option<u8>>>(mut self, ihl: T) -> Self {
        let ihl = ihl.into();
        self.ihl = ihl;
        self
    }
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }
    pub fn src<T: Into<Ipv4Address>>(mut self, src: T) -> Self {
        let src = src.into();
        self.src = src;
        self
    }
    pub fn dst<T: Into<Ipv4Address>>(mut self, dst: T) -> Self {
        let dst = dst.into();
        self.dst = dst;
        self
    }
    pub fn options<T: Into<Vec<IpOption>>>(mut self, options: T) -> Self {
        let options = options.into();
        self.options = options;
        self
    }
    */
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
            src: Ipv4Address::new(127, 0, 0, 1),
            dst: Ipv4Address::new(127, 0, 0, 1),
            options: vec![],
        }
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
