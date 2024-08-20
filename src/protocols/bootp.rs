use crate::typ::string::*;
use crate::*;
use serde::{Deserialize, Serialize};
use strum::{Display, FromRepr};
use typenum::{U128, U16, U60, U64}; // FixedSizeString;
/*
 * Bootp encapsulation
 */

const DHCP_COOKIE_VAL: u32 = 0x63825363;

#[derive(FromRepr, Display, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
enum VendorOptions {
    Pad = 0,
    End = 255,
}

#[derive(FromRepr, Display, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
enum DhcpOption {
    End = 255,                                     // 255 - no length
    Pad = 0,                                       // 0 - no length
    SubnetMask(Ipv4Address),                       // 1
    TimeOffset(i32),                               // 2
    Router(Vec<Ipv4Address>),                      // 3
    TimeServer(Vec<Ipv4Address>),                  // 4
    NameServer(Vec<Ipv4Address>),                  // 5
    DnsServer(Vec<Ipv4Address>),                   // 6
    LogServer(Vec<Ipv4Address>),                   // 7
    CookieServer(Vec<Ipv4Address>),                // 8
    LprServer(Vec<Ipv4Address>),                   // 9
    ImpressServer(Vec<Ipv4Address>),               // 10
    RlocServer(Vec<Ipv4Address>),                  // 11
    HostName(String),                              // 12
    BootFileSize(u16),                             // 13
    MeritDumpFile(String),                         // 14
    DomainName(String),                            // 15
    SwapServer(Ipv4Address),                       // 16
    RootPath(String),                              // 17
    ExtensionsPath(String),                        // 18
    IpForwarding(u8),                              // 19
    NonLocalSrcRouting(u8),                        // 20
    PolicyFilter(Vec<(Ipv4Address, Ipv4Address)>), // 21
    MaxReassemblySize(u16),                        // 22
    DefaultTTL(u8),                                // 23
    PmtudAgingTimeout(u32),                        // 24
    PmtudPlateauTable(Vec<u16>),                   // 25
    InterfaceMtu(u16),                             // 26
    AllSubnetsAreLocal(u8),                        // 27
    BroadcastAddress(Ipv4Address),                 // 28
    PerformMaskDiscovery(u8),                      // 29
    MaskSupplier(u8),                              // 30
    PerformRouterDiscovery(u8),                    // 31
    RouterSolicitationAddress(Ipv4Address),        // 32
    StaticRoute(Vec<(Ipv4Address, Ipv4Address)>),  // 33
    TrailerEncapsulation(u8),                      // 34
    ArpCacheTimeout(u32),                          // 35
    EthernetEncapsulation(u8),                     // 36
    TcpDefaultTtl(u8),                             // 37
    TcpKeepaliveInterval(u32),                     // 38
    TcpKeepaliveGarbage(u8),                       // 39
    NisDomain(String),                             // 40
    NisServers(Vec<Ipv4Address>),                  // 41
    NtpServers(Vec<Ipv4Address>),                  // 42
    VendorSpecific(Vec<VendorOptions>),            // 43
    NetBiosNameServer(Vec<Ipv4Address>),           // 44
    NetBiosDatagramServer(Vec<Ipv4Address>),       // 45
    NetBiosNodeType(u8),                           // 46
    NetBiosScope(String),                          // 47
    XWindowsFontServer(Vec<Ipv4Address>),          // 48
    XWindowsDisplayManager(Vec<Ipv4Address>),      // 49
    RequestedIpAddress(Ipv4Address),               // 50
    AddressLeaseTime(u32),                         // 51
    OptionOverload(u8),                            // 52
    DhcpMessageType(DhcpMessageType),              // 53
    ServerIdentifier(Ipv4Address),                 // 54
    ParameterRequestList(Vec<u8>),                 // 55
    NakMessage(String),                            // 56
    MaxDhcpMessageSize(u16),                       // 57
    RenewalT1Value(u32),                           // 58
    RebindT2Value(u32),                            // 59
    ClientClass(Vec<u8>),                          // 60
    ClientIdentifier((u8, Vec<u8>)),               // 61
}

impl Default for DhcpOption {
    fn default() -> Self {
        DhcpOption::Pad
    }
}

#[derive(FromRepr, Display, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DhcpMessageType {
    DhcpDiscover = 1,
    DhcpOffer,
    DhcpRequest,
    DhcpDecline,
    DhcpAck,
    DhcpNak,
    DhcpRelease,
}

impl Default for DhcpMessageType {
    fn default() -> Self {
        DhcpMessageType::DhcpDiscover
    }
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(BOOTP_VENDORS, VendorCookie = DHCP_COOKIE_VAL))]
pub struct Dhcp {
    #[nproto(decode = decode_dhcp_opts, encode = encode_dhcp_opts)]
    pub options: Vec<DhcpOption>,
}

fn decode_dhcp_opts<D: Decoder>(buf: &[u8], me: &mut Dhcp) -> Option<(Vec<DhcpOption>, usize)> {
    let mut ci = 0;
    let mut out: Vec<DhcpOption> = vec![];
    while ci < buf.len() {
        match buf[ci] {
            0 => {
                out.push(DhcpOption::Pad);
                ci += 1;
            }
            255 => {
                out.push(DhcpOption::End);
                ci += 1;
                break;
            }
            x => {
	        // FIXME: this only fills with "default" value
                if let Some(o) = DhcpOption::from_repr(x) {
                    out.push(o);
                    ci += 2 + buf[ci + 1] as usize;
                } else {
                    break;
                }
            }
        }
    }
    Some((out, ci))
}

fn encode_dhcp_opts<E: Encoder>(
    my_layer: &Dhcp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    // FIXME
    vec![]
}

#[nproto(register(UDP_DST_PORT_APPS, DstPort = 67))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 67))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 68))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 68))]
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Bootp {
    #[nproto(default = 0x01)] // "Request" by default
    pub op: Value<u8>,
    pub htype: Value<u8>,  // hardware address type
    pub hlen: Value<u8>,   // hardware address length
    pub hops: Value<u8>,   // client sets to zero
    pub xid: Value<u32>,   // transaction ID
    pub secs: Value<u16>,  // seconds since client started trying to boot
    pub flags: Value<u16>, // 0x8000 = broadcast
    #[nproto(default = "0.0.0.0")]
    pub ciaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub yiaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub siaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub giaddr: Value<Ipv4Address>,
    chaddr: Value<FixedSizeString<U16>>, // client hardware address filled by client
    sname: Value<FixedSizeString<U64>>,  // optional server host name, null terminated str
    file: Value<FixedSizeString<U128>>,  // boot file name, null terminated string
    #[nproto(default = 0x123456)]
    #[nproto(next: BOOTP_VENDORS => VendorCookie)]
    cookie: Value<u32>,
    #[nproto(decode = decode_vend, encode = encode_vend)]
    vend: Value<BootpVendorData>, // Optional vendor specific area
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum BootpVendorData {
    Unset,
    Set(FixedSizeString<U60>),
}

impl Distribution<BootpVendorData> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BootpVendorData {
        // FIXME: rng.gen(),
        BootpVendorData::Unset
    }
}

impl Default for BootpVendorData {
    fn default() -> Self {
        Self::Unset
    }
}

impl FromStr for BootpVendorData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 0 {
            Ok(BootpVendorData::Unset)
        } else {
            Ok(BootpVendorData::Set(FixedSizeString::<U60>::from_str(s)?))
        }
    }
}

fn decode_vend<D: Decoder>(buf: &[u8], me: &mut Bootp) -> Option<(BootpVendorData, usize)> {
    let mut ci = 0;
    if me.cookie == Value::Set(DHCP_COOKIE_VAL) {
        Some((BootpVendorData::Unset, 0))
    } else {
        let (the_vec, _) = D::decode_vec(buf, 60)?;
        // FIXME
        Some((BootpVendorData::Unset, 0))
        // Some((BootpVendorData::Set(the_vec), 60))
    }
}

fn encode_vend<E: Encoder>(
    my_layer: &Bootp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    // FIXME
    vec![]
}
