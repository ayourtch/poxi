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
extern crate itertools;
extern crate mac_address;

pub struct ParseNumberError;
use crate::Value::Random;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

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
pub enum Value<T> {
    Auto,
    Random,
    Set(T),
}

impl<T: Copy> Value<T> {
    fn value(&self) -> T {
        match self {
            Self::Auto => panic!("can not return auto value"),
            Self::Random => unimplemented!(),
            Self::Set(x) => *x,
        }
    }
}

impl<T: std::cmp::PartialEq> Value<T> {
    fn is_auto(&self) -> bool {
        self == &Self::Auto
    }
}

impl<T: std::fmt::Display> fmt::Display for Value<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str(&format!("Auto")),
            Self::Random => f.write_str(&format!("Random")),
            Self::Set(x) => x.fmt(f),
        }
    }
}

impl<T: std::fmt::Debug> fmt::Debug for Value<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str(&format!("Auto")),
            Self::Random => f.write_str(&format!("Random")),
            Self::Set(x) => f.write_str(&format!("{:?}", &x)),
        }
    }
}

impl<T> Default for Value<T> {
    fn default() -> Self {
        Self::Auto
    }
}

impl<'a, T: From<&'a str>> From<&'a str> for Value<T> {
    fn from(s: &'a str) -> Self {
        Self::Set(T::from(s))
    }
}

/*
impl<T, V> From<V> for Value<T>
where T: From<V>, V: FromStr
{
    fn from(v: V) -> Self {
        Self::Set(v)
    }
}
*/

pub enum ValueParseError {
    Error,
}

impl<T: FromStr> FromStr for Value<T> {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match T::from_str(s) {
            Ok(res) => Ok(Self::Set(res)),
            Err(e) => panic!("Could not parse!"),
        }
    }
}

#[derive(PartialEq, Clone, Eq)]
pub struct MacAddr(mac_address::MacAddress);

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", &self.0))
    }
}

impl Default for MacAddr {
    fn default() -> Self {
        MacAddr(mac_address::MacAddress::new([0, 0, 0, 0, 0, 0]))
    }
}

impl MacAddr {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8, o5: u8, o6: u8) -> Self {
        MacAddr(mac_address::MacAddress::new([o1, o2, o3, o4, o5, o6]))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseMacAddrError;

impl FromStr for MacAddr {
    type Err = ParseMacAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = s.parse();
        if res.is_err() {
            return Err(ParseMacAddrError);
        }
        Ok(MacAddr(res.unwrap()))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(arg: [u8; 6]) -> Self {
        Self::new(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5])
    }
}

impl From<Value<MacAddr>> for MacAddr {
    fn from(v: Value<MacAddr>) -> MacAddr {
        match v {
            Value::Auto => {
                panic!("can not return value of auto mac addr");
            }
            Value::Random => {
                unimplemented!();
            }
            Value::Set(x) => x.clone(),
        }
    }
}

impl From<&str> for MacAddr {
    fn from(s: &str) -> Self {
        let res = s.parse().unwrap();
        MacAddr(res)
    }
}

impl Distribution<MacAddr> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MacAddr {
        MacAddr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        )
    }
}

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

impl Distribution<Ipv4Address> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Ipv4Address {
        Ipv4Address::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())
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

fn parse_pair_as_value<T>(v: &str) -> Value<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => Value::Set(val),
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

#[derive(Clone, Debug, Default)]
pub struct EncodingVecVec {
    data: Vec<Vec<u8>>,
    curr_idx: usize,
}

impl EncodingVecVec {
    fn len(&self) -> usize {
        // take into account the "phantom" layers
        self.data.len() + self.curr_idx + 1
    }
}
impl Index<usize> for EncodingVecVec {
    type Output = Vec<u8>;

    fn index(&self, idx: usize) -> &Self::Output {
        if idx > self.curr_idx {
            &self.data[idx - self.curr_idx - 1]
        } else {
            panic!("encoding data at layer {} not yet ready", idx);
        }
    }
}

#[derive(Clone)]
pub struct LayerStack {
    pub layers: Vec<Box<dyn Layer>>,
}

impl LayerStack {
    pub fn g<T: Layer>(&self, idx: T) -> &T {
        self[TypeId::of::<T>()].downcast_ref().unwrap()
    }

    pub fn item_at<T: Layer>(&self, item: T, idx: usize) -> Option<&T> {
        self.layers[idx].downcast_ref()
    }

    pub fn items_of<T: Layer>(&self, item: T) -> Vec<&T> {
        let mut out = vec![];
        for ll in &self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                out.push(ll.downcast_ref().unwrap())
            }
        }
        out
    }

    pub fn encode(self) -> Vec<u8> {
        let mut out = EncodingVecVec {
            data: vec![],
            curr_idx: self.layers.len(),
        };
        for (i, ll) in (&self.layers).into_iter().enumerate().rev() {
            out.curr_idx = i;
            println!("{}: {:?}", i, &ll);
            let ev = ll.encode(&self, i, &out);
            out.data.push(ev);
        }
        out.data.reverse();
        itertools::concat(out.data)
    }

    pub fn fill(&self) -> LayerStack {
        let mut out = LayerStack { layers: vec![] };
        for (i, ll) in (&self.layers).into_iter().enumerate() {
            ll.fill(&self, i, &mut out);
        }
        out
    }

    pub fn indices_of<T: Layer>(&self, typ: T) -> Vec<usize> {
        let mut out = vec![];
        for (i, ref layer) in (&self.layers).into_iter().enumerate() {
            if layer.type_id_is(typ.type_id()) {
                out.push(i)
            }
        }
        out
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
    /* fill the unknown fields based on the entire stack contents */
    fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack);
    fn encode(
        &self,
        stack: &LayerStack,
        my_index: usize,
        encoded_layers: &EncodingVecVec,
    ) -> Vec<u8>;
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

fn fill_dmac(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> MacAddr {
    MacAddr::from("ff:ff:ff:ff:ff:ff")
}
fn fill_crc(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u32 {
    0x1234
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(encoder(BinaryBigEndian))]
pub struct ether {
    #[nproto(fill = fill_dmac, default = "01:02:03:04:05:06")]
    // #[nproto(default = "01:02:03:04:05:06")]
    // #[nproto(fill = fill_dmac)]
    // #[nproto(default = Random)]
    pub dst: Value<MacAddr>,
    #[nproto(fill = "00:00:00:00:00:00")]
    pub src: Value<MacAddr>,
    #[nproto(fill = 42)]
    pub len: Value<u16>,
    #[nproto(fill = fill_crc)]
    pub crc: Value<u32>,
}

fn encode_csum(
    layer: &dyn Layer,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> u16 {
    0xffff
}

fn fill_udp_sport(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u16 {
    0xffff
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
pub struct Udp {
    #[nproto(fill = fill_udp_sport)]
    pub sport: Value<u16>,
    pub dport: Value<u16>,
    pub len: Value<u16>,
    #[nproto(auto = encode_csum)]
    pub chksum: Value<u16>,
}

use std::num::ParseIntError;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IpFlags {
    // FIXME
}

impl From<u8> for IpFlags {
    fn from(v: u8) -> Self {
        IpFlags {}
    }
}
impl FromStr for IpFlags {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpFlags {})
    }
}

impl Distribution<IpFlags> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> IpFlags {
        IpFlags {}
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
    #[nproto(default = 4)]
    pub version: Value<u8>,
    pub ihl: Value<u8>,
    pub tos: Value<u8>,
    pub len: Value<u16>,
    #[nproto(default = Random)]
    pub id: Value<u16>,
    pub flags: Value<IpFlags>,
    pub frag: Value<u16>,
    #[nproto(default = 64)]
    pub ttl: Value<u8>,
    pub proto: Value<u8>,
    pub chksum: Value<u16>,
    #[nproto(default = "127.0.0.1")]
    pub src: Value<Ipv4Address>,
    #[nproto(default = "127.0.0.1")]
    pub dst: Value<Ipv4Address>,
    pub options: Vec<IpOption>,
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
