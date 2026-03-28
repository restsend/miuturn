use bytes::{BufMut, Bytes, BytesMut};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    Binding = 0x0001,
    Allocate = 0x0003,
    Refresh = 0x0004,
    Send = 0x0006,
    Data = 0x0007,
    ChannelBind = 0x0009,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EventType {
    Request = 0,
    Indication = 1,
    Success = 2,
    Error = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    TryAlternate = 300,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    AllocationMismatch = 437,
    StaleCredentials = 438,
    UnsupportedTransport = 442,
    AllocationQuotaReached = 486,
    RoleConflict = 487,
    ServerError = 500,
}

impl ErrorCode {
    pub fn code(&self) -> u16 {
        *self as u16
    }
}

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub method: Method,
    pub event_type: EventType,
    pub message_length: u16,
    pub magic_cookie: u32,
    pub transaction_id: [u8; 12],
}

impl MessageHeader {
    /// Parse STUN message header - zero-copy version
    #[inline]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        // Check for magic cookie at byte 4-7 (RFC 5389)
        if data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42 {
            // Fast path: read directly from bytes without allocating
            let msg_type = u16::from_be_bytes([data[0], data[1]]);
            let first_byte = (msg_type >> 8) as u8;
            let second_byte = (msg_type & 0xFF) as u8;
            let class = (first_byte & 0x01) | ((second_byte & 0x10) >> 3);
            let method_val = (((first_byte & 0x3E) as u16) << 7) | ((second_byte & 0x0F) as u16);
            let method = match method_val {
                0x0001 => Method::Binding,
                0x0003 => Method::Allocate,
                0x0004 => Method::Refresh,
                0x0006 => Method::Send,
                0x0007 => Method::Data,
                0x0009 => Method::ChannelBind,
                _ => return None,
            };
            let event_type = match class {
                0 => EventType::Request,
                1 => EventType::Indication,
                2 => EventType::Success,
                3 => EventType::Error,
                _ => return None,
            };
            let message_length = u16::from_be_bytes([data[2], data[3]]);
            let magic_cookie = 0x2112A442u32;
            let mut transaction_id = [0u8; 12];
            transaction_id.copy_from_slice(&data[8..20]);

            return Some(MessageHeader {
                method,
                event_type,
                message_length,
                magic_cookie,
                transaction_id,
            });
        }

        // RFC 3489 format fallback
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let first_byte = (msg_type >> 8) as u8;
        let second_byte = (msg_type & 0xFF) as u8;
        let class = (first_byte & 0x01) | ((second_byte & 0x10) >> 3);
        let method_val = (((first_byte & 0x3E) as u16) << 7) | ((second_byte & 0x0F) as u16);
        let method = match method_val {
            0x0001 => Method::Binding,
            0x0003 => Method::Allocate,
            0x0004 => Method::Refresh,
            0x0006 => Method::Send,
            0x0007 => Method::Data,
            0x0009 => Method::ChannelBind,
            _ => return None,
        };
        let event_type = match class {
            0 => EventType::Request,
            1 => EventType::Indication,
            2 => EventType::Success,
            3 => EventType::Error,
            _ => return None,
        };
        let message_length = u16::from_be_bytes([data[2], data[3]]);
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[4..16]);

        Some(MessageHeader {
            method,
            event_type,
            message_length,
            magic_cookie: 0x2112A442,
            transaction_id,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let method_val = self.method as u16;
        let class_val = match self.event_type {
            EventType::Request => 0u16,
            EventType::Indication => 1u16,
            EventType::Success => 2u16,
            EventType::Error => 3u16,
        };
        let first_byte = (((method_val >> 7) & 0x3E) as u8) | ((class_val & 0x01) as u8);
        let second_byte = ((method_val & 0x0F) as u8) | (((class_val & 0x02) << 3) as u8);
        let msg_type = ((first_byte as u16) << 8) | (second_byte as u16);
        buf.put_u16(msg_type);
        buf.put_u16(self.message_length);
        buf.put_u32(self.magic_cookie);
        buf.put_slice(&self.transaction_id);
    }
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub attr_type: u16,
    pub value: Bytes,
}

impl Attribute {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x001C;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const USERNAME: u16 = 0x0016;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const LIFETIME: u16 = 0x000D;
    pub const BANDWIDTH: u16 = 0x0011;
    pub const DATA: u16 = 0x0013;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const PEER_ADDRESS: u16 = 0x0012;
    pub const TRANSPORT: u16 = 0x0019;
    pub const REQUESTED_TRANSPORT: u16 = 0x0009;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const ERROR_CODE_ALT: u16 = 0x000B;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const ICE_CONTROLLING: u16 = 0x8029;
    pub const ICE_CONTROLLED: u16 = 0x802A;

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let attr_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return None;
        }
        let value = Bytes::copy_from_slice(&data[4..4 + length]);
        Some(Attribute { attr_type, value })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let len = self.value.len() as u16;
        let padding = (4 - (len % 4)) % 4;
        buf.put_u16(self.attr_type);
        buf.put_u16(len);
        buf.put_slice(&self.value);
        if padding > 0 {
            buf.put_slice(&[0u8; 4][..padding as usize]);
        }
    }
}

/// Fast STUN Binding success response - optimized for hot path
#[inline]
pub fn create_binding_response_fast(transaction_id: [u8; 12], client_addr: SocketAddr) -> Bytes {
    let mut buf = BytesMut::with_capacity(32 + 8);

    // Header: Binding Success Response
    // msg_type = 0x0001 | class=2 -> encoded as 0x0011
    buf.put_u16(0x0011);
    buf.put_u16(8); // message length: XOR-MAPPED-ADDRESS is 8 bytes
    buf.put_u32(0x2112A442); // magic cookie
    buf.put_slice(&transaction_id);

    // XOR-MAPPED-ADDRESS attribute
    buf.put_u16(0x0020); // attr type
    buf.put_u16(8); // attr length

    match client_addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(0); // reserved
            buf.put_u8(0x01); // IPv4 family
            let port = v4.port() ^ 0x2112;
            buf.put_u16(port);
            let ip = v4.ip().octets();
            buf.put_u8(ip[0] ^ 0x21);
            buf.put_u8(ip[1] ^ 0x12);
            buf.put_u8(ip[2] ^ 0xa4);
            buf.put_u8(ip[3] ^ 0x42);
        }
        SocketAddr::V6(_) => {
            buf.put_u8(0);
            buf.put_u8(0x02); // IPv6 family - simplified, full impl needs more bytes
            buf.put_u16(0); // placeholder
        }
    }

    buf.freeze()
}

pub fn encode_xor_address(addr: SocketAddr, magic_cookie: u32, tid: &[u8; 12]) -> Bytes {
    let mut buf = BytesMut::with_capacity(8);
    match addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(0); // byte 0: padding (decode doesn't use it)
            buf.put_u8(0x01); // byte 1: family
            let ip = v4.ip().octets();
            let xored: [u8; 4] = [
                ip[0] ^ ((magic_cookie >> 24) as u8),
                ip[1] ^ ((magic_cookie >> 16) as u8),
                ip[2] ^ ((magic_cookie >> 8) as u8),
                ip[3] ^ (magic_cookie as u8),
            ];
            buf.put_u16(
                v4.port() ^ (magic_cookie as u16 >> 1) ^ (u16::from_be_bytes([tid[10], tid[11]])),
            );
            buf.put_slice(&xored);
        }
        SocketAddr::V6(_) => {
            buf.put_u8(0); // byte 0: padding
            buf.put_u8(0x02); // byte 1: family
            buf.put_u16(addr.port() ^ (magic_cookie as u16 >> 1));
            buf.put_u32(0); // placeholder
        }
    }
    buf.freeze()
}

pub fn decode_xor_address(data: &[u8], magic_cookie: u32, tid: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]])
        ^ (magic_cookie as u16 >> 1)
        ^ u16::from_be_bytes([tid[10], tid[11]]);
    if family == 0x01 {
        let mut ip = [0u8; 4];
        ip[0] = data[4] ^ ((magic_cookie >> 24) as u8);
        ip[1] = data[5] ^ ((magic_cookie >> 16) as u8);
        ip[2] = data[6] ^ ((magic_cookie >> 8) as u8);
        ip[3] = data[7] ^ (magic_cookie as u8);
        Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub attributes: Vec<Attribute>,
}

impl Message {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = MessageHeader::parse(data)?;
        let mut offset = 20;
        let mut attributes = Vec::new();
        while offset < 20 + header.message_length as usize {
            if let Some(attr) = Attribute::decode(&data[offset..]) {
                let attr_len = attr.value.len() + 4;
                let padding = (4 - (attr_len % 4)) % 4;
                attributes.push(attr);
                offset += attr_len + padding;
            } else {
                break;
            }
        }
        Some(Message { header, attributes })
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let mut attr_buf = BytesMut::new();
        for attr in &self.attributes {
            attr.encode(&mut attr_buf);
        }
        let mut header = self.header.clone();
        header.message_length = attr_buf.len() as u16;
        header.magic_cookie = 0x2112A442;
        header.encode(&mut buf);
        buf.put(attr_buf.freeze());
        buf.freeze()
    }

    pub fn add_attribute(&mut self, attr: Attribute) {
        self.attributes.push(attr);
    }

    pub fn get_attribute(&self, attr_type: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }
}

pub fn create_error_response(header: &MessageHeader, code: ErrorCode) -> Message {
    let mut msg = Message {
        header: MessageHeader {
            method: header.method,
            event_type: EventType::Error,
            message_length: 0,
            magic_cookie: 0x2112A442,
            transaction_id: header.transaction_id,
        },
        attributes: Vec::new(),
    };
    let mut err_buf = BytesMut::new();
    err_buf.put_u32(0);
    err_buf.put_u16(0);
    let class = (code.code() / 100) as u8;
    let number = (code.code() % 100) as u8;
    err_buf.put_u8(class);
    err_buf.put_u8(number);
    let reason = format!("{:?}", code);
    err_buf.put_u8(reason.len() as u8);
    err_buf.put_slice(reason.as_bytes());
    msg.add_attribute(Attribute {
        attr_type: Attribute::ERROR_CODE,
        value: err_buf.freeze(),
    });
    msg
}

pub fn create_success_response(header: &MessageHeader) -> Message {
    Message {
        header: MessageHeader {
            method: header.method,
            event_type: EventType::Success,
            message_length: 0,
            magic_cookie: 0x2112A442,
            transaction_id: header.transaction_id,
        },
        attributes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_header_roundtrip() {
        let header = MessageHeader {
            method: Method::Allocate,
            event_type: EventType::Success,
            message_length: 0,
            magic_cookie: 0x2112A442,
            transaction_id: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        };
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let encoded = buf.freeze();
        let parsed = MessageHeader::parse(&encoded);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert_eq!(p.method, Method::Allocate);
    }

    #[test]
    fn test_attribute_encode_decode() {
        let attr = Attribute {
            attr_type: Attribute::REALM,
            value: Bytes::from_static(b"test"),
        };
        let mut buf = BytesMut::new();
        attr.encode(&mut buf);
        let encoded = buf.freeze();
        let decoded = Attribute::decode(&encoded).unwrap();
        assert_eq!(decoded.attr_type, attr.attr_type);
        assert_eq!(decoded.value, attr.value);
    }

    #[test]
    fn test_xor_address_v4() {
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let magic = 0x2112A442;
        let tid = [0u8; 12];
        let encoded = encode_xor_address(addr, magic, &tid);
        let decoded = decode_xor_address(&encoded, magic, &tid).unwrap();
        assert_eq!(addr.port(), decoded.port());
    }

    #[test]
    fn test_message_roundtrip() {
        let msg = Message {
            header: MessageHeader {
                method: Method::Allocate,
                event_type: EventType::Success,
                message_length: 0,
                magic_cookie: 0x2112A442,
                transaction_id: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            },
            attributes: vec![Attribute {
                attr_type: Attribute::REALM,
                value: Bytes::from_static(b"test"),
            }],
        };
        let encoded = msg.encode();
        let parsed = Message::parse(&encoded);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().header.method, Method::Allocate);
    }

    #[test]
    fn test_fast_binding_response() {
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let tid = [0u8; 12];
        let response = create_binding_response_fast(tid, addr);
        assert_eq!(response.len(), 32); // 20-byte header + 12-byte XOR-MAPPED-ADDRESS attribute

        // Verify it can be parsed
        let parsed = Message::parse(&response);
        assert!(parsed.is_some());
        let msg = parsed.unwrap();
        assert_eq!(msg.header.method, Method::Binding);
        assert_eq!(msg.header.event_type, EventType::Success);
    }
}
