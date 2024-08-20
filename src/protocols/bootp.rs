use crate::typ::string::*;
use crate::*;
use typenum::{U128, U16, U64}; // FixedSizeString;

/*
 * Bootp encapsulation
 */

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 67))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 67))]

// #[nproto(register(UDP_DST_PORT_APPS, DstPort = 68))]
// #[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 68))]
pub struct Bootp {
    #[nproto(default = 0x01)] // "Request" by default
    pub op: Value<u8>,
    pub htype: Value<u8>, // hardware address type
    pub hlen: Value<u8>,  // hardware address length
    pub hops: Value<u8>,  // client sets to zero
    pub xid: Value<u32>,  // transaction ID
    pub secs: Value<u16>, // seconds since client started trying to boot
    pub unused: Value<u16>,
    #[nproto(default = "0.0.0.0")]
    pub ciaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub yiaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub siaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub giaddr: Value<Ipv4Address>,
    chaddr: Value<FixedSizeString::<U16>>, // client hardware address filled by client
    sname: Value<FixedSizeString::<U16>>,  // optional server host name, null terminated str
    file: Value<FixedSizeString::<U128>>,  // boot file name, null terminated string
    vend: Value<FixedSizeString::<U128>>,  // Optional vendor specific area
}
