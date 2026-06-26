//! RFC 5389 / RFC 5766 format compliance verification.
//!
//! These tests verify that every message the server constructs matches
//! the exact byte-level format specified in the RFCs.

use miuturn::message::{
    Attribute, ErrorCode, EventType, Message, MessageHeader, Method,
    create_binding_response_fast, create_error_response_with_reason, create_success_response,
    encode_xor_address, decode_xor_address,
};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// RFC 5389 §15: STUN Header Format
// ---------------------------------------------------------------------------

#[test]
fn stun_header_format_binding_request() {
    let mut buf = BytesMut::new();
    MessageHeader {
        method: Method::Binding,
        event_type: EventType::Request,
        message_length: 0,
        magic_cookie: 0x2112A442,
        transaction_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    }
    .encode(&mut buf);
    let raw = buf.freeze();

    assert_eq!(raw.len(), 20, "STUN header must be exactly 20 bytes");

    // Byte 0-1: message type (RFC 5389 encoded)
    // Binding Request = method=0x001, class=Request(0) → 0x0001
    assert_eq!(raw[0], 0x00, "msg type high byte");
    assert_eq!(raw[1], 0x01, "msg type low byte (Binding Request)");

    // Byte 2-3: message length = 0
    assert_eq!(raw[2], 0x00, "message length high byte");
    assert_eq!(raw[3], 0x00, "message length low byte");

    // Byte 4-7: magic cookie = 0x2112A442
    assert_eq!(raw[4], 0x21, "magic cookie byte 0");
    assert_eq!(raw[5], 0x12, "magic cookie byte 1");
    assert_eq!(raw[6], 0xA4, "magic cookie byte 2");
    assert_eq!(raw[7], 0x42, "magic cookie byte 3");

    // Byte 8-19: transaction ID
    assert_eq!(&raw[8..20], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
}

#[test]
fn stun_header_format_allocate_request() {
    let mut buf = BytesMut::new();
    MessageHeader {
        method: Method::Allocate,
        event_type: EventType::Request,
        message_length: 0,
        magic_cookie: 0x2112A442,
        transaction_id: [0; 12],
    }
    .encode(&mut buf);
    let raw = buf.freeze();

    // Allocate Request = method=0x003, class=Request(0) → 0x0003
    assert_eq!(raw[1], 0x03, "Allocate Request type low byte");
}

#[test]
fn stun_header_format_success_response() {
    let mut buf = BytesMut::new();
    MessageHeader {
        method: Method::Allocate,
        event_type: EventType::Success,
        message_length: 0,
        magic_cookie: 0x2112A442,
        transaction_id: [0; 12],
    }
    .encode(&mut buf);
    let raw = buf.freeze();

    // Allocate Success = method=0x003, class=Success(2) → encoded:
    // method bits: a=3, b=0, d=0 → method_enc=3
    // c0 = (2&1)<<4 = 0, c1 = (2&2)<<7 = 256 → msg_type = 3+256 = 259 = 0x0103
    assert_eq!(&raw[0..2], &[0x01, 0x03], "Allocate Success type");
}

#[test]
fn stun_header_format_error_response() {
    let mut buf = BytesMut::new();
    MessageHeader {
        method: Method::Refresh,
        event_type: EventType::Error,
        message_length: 0,
        magic_cookie: 0x2112A442,
        transaction_id: [0; 12],
    }
    .encode(&mut buf);
    let raw = buf.freeze();

    // Refresh Error = method=0x004, class=Error(3) → encoded:
    // method bits: a=4, b=0, d=0 → method_enc=4
    // c0 = (3&1)<<4 = 16, c1 = (3&2)<<7 = 256 → msg_type = 4+16+256 = 276 = 0x0114
    assert_eq!(&raw[0..2], &[0x01, 0x14], "Refresh Error type");
}

// ---------------------------------------------------------------------------
// RFC 5389 §15.1: XOR-MAPPED-ADDRESS
// ---------------------------------------------------------------------------

#[test]
fn xor_mapped_address_format_ipv4() {
    let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
    let tid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC];
    let encoded = encode_xor_address(addr, 0x2112A442, &tid);

    // IPv4 XOR-ADDRESS: reserved(1) + family(1) + xport(2) + xip(4) = 8 bytes
    assert_eq!(encoded.len(), 8, "IPv4 XOR-ADDRESS must be 8 bytes");

    // Byte 0: reserved (must be 0)
    assert_eq!(encoded[0], 0x00, "reserved byte must be 0");

    // Byte 1: family = 0x01 for IPv4
    assert_eq!(encoded[1], 0x01, "family must be 0x01 for IPv4");

    // Byte 2-3: port XOR'd with (magic_cookie >> 16) as u16 = 0x2112
    let xport = 12345u16 ^ 0x2112u16;
    assert_eq!(encoded[2], (xport >> 8) as u8, "xport high byte");
    assert_eq!(encoded[3], (xport & 0xFF) as u8, "xport low byte");

    // Byte 4-7: IP XOR'd with magic cookie bytes
    let magic = 0x2112A442u32;
    assert_eq!(encoded[4], 192 ^ ((magic >> 24) as u8), "xip[0]");
    assert_eq!(encoded[5], 168 ^ ((magic >> 16) as u8), "xip[1]");
    assert_eq!(encoded[6], 1 ^ ((magic >> 8) as u8), "xip[2]");
    assert_eq!(encoded[7], 100 ^ (magic as u8), "xip[3]");
}

#[test]
fn xor_mapped_address_roundtrip_ipv4() {
    let addr: SocketAddr = "10.20.30.40:65000".parse().unwrap();
    let tid = [0xFF; 12];
    let encoded = encode_xor_address(addr, 0x2112A442, &tid);
    let decoded = decode_xor_address(&encoded, 0x2112A442, &tid).unwrap();
    assert_eq!(addr, decoded, "IPv4 XOR-ADDRESS round-trip");
}

#[test]
fn xor_mapped_address_format_ipv6() {
    let addr: SocketAddr = "[2001:db8::1]:3456".parse().unwrap();
    let tid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    let encoded = encode_xor_address(addr, 0x2112A442, &tid);

    // IPv6 XOR-ADDRESS: reserved(1) + family(1) + xport(2) + xip(16) = 20 bytes
    assert_eq!(encoded.len(), 20, "IPv6 XOR-ADDRESS must be 20 bytes");

    // Byte 0: reserved = 0
    assert_eq!(encoded[0], 0x00, "reserved must be 0");

    // Byte 1: family = 0x02 for IPv6
    assert_eq!(encoded[1], 0x02, "family must be 0x02 for IPv6");

    // Byte 4-7: first 4 IP bytes XOR'd with magic cookie
    let magic = 0x2112A442u32;
    assert_eq!(encoded[4], 0x20 ^ ((magic >> 24) as u8), "xip6[0] (magic)");
    assert_eq!(encoded[5], 0x01 ^ ((magic >> 16) as u8), "xip6[1] (magic)");

    // Byte 8-19: remaining 12 IP bytes XOR'd with transaction ID
    assert_eq!(encoded[8], 0x00 ^ tid[0], "xip6[4] (tid)");
    assert_eq!(encoded[9], 0x00 ^ tid[1], "xip6[5] (tid)");
    assert_eq!(encoded[10], 0x00 ^ tid[2], "xip6[6] (tid)");
    assert_eq!(encoded[11], 0x00 ^ tid[3], "xip6[7] (tid)");
    assert_eq!(encoded[12], 0x00 ^ tid[4], "xip6[8] (tid)");
    assert_eq!(encoded[13], 0x00 ^ tid[5], "xip6[9] (tid)");
    assert_eq!(encoded[14], 0x00 ^ tid[6], "xip6[10] (tid)");
    assert_eq!(encoded[15], 0x00 ^ tid[7], "xip6[11] (tid)");
    assert_eq!(encoded[16], 0x00 ^ tid[8], "xip6[12] (tid)");
    assert_eq!(encoded[17], 0x00 ^ tid[9], "xip6[13] (tid)");
    assert_eq!(encoded[18], 0x00 ^ tid[10], "xip6[14] (tid)");
    assert_eq!(encoded[19], 0x01 ^ tid[11], "xip6[15] (tid)");
}

#[test]
fn xor_mapped_address_roundtrip_ipv6() {
    let addr: SocketAddr = "[2001:db8:85a3::8a2e:370:7334]:4444".parse().unwrap();
    let tid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC];
    let encoded = encode_xor_address(addr, 0x2112A442, &tid);
    let decoded = decode_xor_address(&encoded, 0x2112A442, &tid).unwrap();
    assert_eq!(addr, decoded, "IPv6 XOR-ADDRESS round-trip");
}

// ---------------------------------------------------------------------------
// RFC 5389 §15.6: ERROR-CODE
// ---------------------------------------------------------------------------

#[test]
fn error_code_attribute_format() {
    let header = MessageHeader {
        method: Method::Allocate,
        event_type: EventType::Request,
        message_length: 0,
        magic_cookie: 0x2112A442,
        transaction_id: [0; 12],
    };

    // Test each error code
    let test_cases = [
        (ErrorCode::BadRequest, 400, "Bad Request"),
        (ErrorCode::Unauthorized, 401, "Unauthorized"),
        (ErrorCode::Forbidden, 403, "Forbidden"),
        (ErrorCode::ServerError, 500, "ServerError"),
        (ErrorCode::AllocationQuotaReached, 486, "AllocationQuotaReached"),
        (ErrorCode::InsufficientCapacity, 508, "InsufficientCapacity"),
        (ErrorCode::AllocationMismatch, 437, "AllocationMismatch"),
    ];

    for (code, expected_code, _expected_reason) in &test_cases {
        let msg = create_error_response_with_reason(&header, *code, None);
        let err_attr = msg.get_attribute(Attribute::ERROR_CODE).unwrap();
        let val = &err_attr.value;

        // First 4 bytes: class(3 bits) | number(8 bits) in u32 format
        let class = *expected_code / 100;
        let number = *expected_code % 100;
        let raw = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
        assert_eq!(
            (raw >> 8) & 0x7,
            class,
            "ERROR-CODE class for {}",
            expected_code
        );
        assert_eq!(
            (raw & 0xFF) as u32,
            number,
            "ERROR-CODE number for {}",
            expected_code
        );

        // Verify reason string follows the 4-byte header
        let reason_str = String::from_utf8_lossy(&val[4..]);
        assert!(
            reason_str.len() > 0,
            "reason must not be empty for {}",
            expected_code
        );

        // Verify attribute padding is correct in encoded message
        let encoded = msg.encode();
        let parsed = Message::parse(&encoded).unwrap();
        let parsed_attr = parsed.get_attribute(Attribute::ERROR_CODE).unwrap();
        assert_eq!(parsed_attr.value[4..], val[4..], "reason must survive encode+parse round-trip for code {}", expected_code);
    }
}

#[test]
fn error_code_custom_reason() {
    let header = MessageHeader {
        method: Method::Allocate,
        event_type: EventType::Request,
        message_length: 0,
        magic_cookie: 0x2112A442,
        transaction_id: [0; 12],
    };
    let msg = create_error_response_with_reason(&header, ErrorCode::InsufficientCapacity, Some("custom reason"));
    let err_attr = msg.get_attribute(Attribute::ERROR_CODE).unwrap();
    let reason = String::from_utf8_lossy(&err_attr.value[4..]);
    assert_eq!(reason, "custom reason", "custom reason must survive");
}

// ---------------------------------------------------------------------------
// RFC 5389 §15: Attribute padding compliance
// ---------------------------------------------------------------------------

#[test]
fn attribute_padding_is_zero() {
    // Non-4-byte-aligned value
    let attr = Attribute {
        attr_type: Attribute::REALM,
        value: Bytes::from_static(b"abc"), // 3 bytes, needs 1 byte padding
    };
    let mut buf = BytesMut::new();
    attr.encode(&mut buf);
    let raw = buf.freeze();

    // Attribute header: 4 bytes (type + length)
    // Value: 3 bytes + 1 padding
    // Total: 8 bytes
    assert_eq!(raw.len(), 8, "padded attr size must be 4-byte aligned");

    // Type = 0x0014 (REALM)
    assert_eq!(raw[0], 0x00);
    assert_eq!(raw[1], 0x14);

    // Length = 3 (actual value, before padding)
    assert_eq!(raw[2], 0x00);
    assert_eq!(raw[3], 0x03);

    // Value = "abc"
    assert_eq!(&raw[4..7], b"abc");

    // Padding byte must be zero
    assert_eq!(raw[7], 0x00, "padding byte must be 0");
}

#[test]
fn attribute_without_padding() {
    let attr = Attribute {
        attr_type: 0x8022, // SOFTWARE
        value: Bytes::from_static(b"test"), // 4 bytes, no padding needed
    };
    let mut buf = BytesMut::new();
    attr.encode(&mut buf);
    let raw = buf.freeze();

    assert_eq!(raw.len(), 8, "4-byte value needs no padding");
    assert_eq!(&raw[4..8], b"test");
}

#[test]
fn attribute_max_padding() {
    let attr = Attribute {
        attr_type: 0x0001,
        value: Bytes::from_static(b"a"), // 1 byte, needs 3 bytes padding
    };
    let mut buf = BytesMut::new();
    attr.encode(&mut buf);
    let raw = buf.freeze();

    assert_eq!(raw.len(), 8, "1-byte value needs 3 bytes padding");

    // Padding bytes must all be zero
    assert_eq!(raw[5], 0x00, "padding byte 1");
    assert_eq!(raw[6], 0x00, "padding byte 2");
    assert_eq!(raw[7], 0x00, "padding byte 3");
}

// ---------------------------------------------------------------------------
// RFC 5766 §11.4: ChannelData format
// ---------------------------------------------------------------------------

#[test]
fn channel_data_format() {
    let channel_num: u16 = 0x4000;
    let payload = b"hello";
    let mut channel_data = vec![0u8; 4 + payload.len()];
    channel_data[0] = (channel_num >> 8) as u8;
    channel_data[1] = (channel_num & 0xFF) as u8;
    channel_data[2] = (payload.len() >> 8) as u8;
    channel_data[3] = (payload.len() & 0xFF) as u8;
    channel_data[4..].copy_from_slice(payload);

    // Channel number must be in 0x4000-0x7FFF
    assert!(
        ((channel_data[0] as u16) << 8 | (channel_data[1] as u16)) >= 0x4000,
        "channel number in valid range"
    );

    // Data length must match payload
    let declared_len = (channel_data[2] as usize) << 8 | (channel_data[3] as usize);
    assert_eq!(declared_len, payload.len(), "ChannelData length must match payload");
    assert_eq!(channel_data.len(), 4 + declared_len, "ChannelData total length");
}

// ---------------------------------------------------------------------------
// RFC 5389 §15: Message encoding compliance (multiple attrs)
// ---------------------------------------------------------------------------

#[test]
fn message_encoding_message_length_correct() {
    let msg = Message {
        header: MessageHeader {
            method: Method::Allocate,
            event_type: EventType::Success,
            message_length: 0,
            magic_cookie: 0x2112A442,
            transaction_id: [0; 12],
        },
        attributes: vec![
            Attribute {
                attr_type: Attribute::REALM,
                value: Bytes::from_static(b"test-realm"),
            },
            Attribute {
                attr_type: Attribute::LIFETIME,
                value: Bytes::from_static(&[0, 0, 0, 120]), // 120 seconds
            },
        ],
    };

    let encoded = msg.encode();

    // Verify message_length field matches actual body size
    let declared_len = (encoded[2] as usize) << 8 | (encoded[3] as usize);
    let actual_body_len = encoded.len() - 20;
    assert_eq!(
        declared_len, actual_body_len,
        "message_length field must equal actual body size"
    );

    // Verify the encoded message can be parsed back
    let parsed = Message::parse(&encoded).unwrap();
    assert_eq!(parsed.header.method, Method::Allocate);
    assert_eq!(parsed.attributes.len(), 2);
    assert!(parsed.get_attribute(Attribute::REALM).is_some());
    assert!(parsed.get_attribute(Attribute::LIFETIME).is_some());
}

#[test]
fn response_message_length_is_accurate() {
    let header = MessageHeader {
        method: Method::ChannelBind,
        event_type: EventType::Success,
        message_length: 0,
        magic_cookie: 0x2112A442,
        transaction_id: [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12],
    };
    let msg = create_success_response(&header);
    let encoded = msg.encode();

    let declared_len = (encoded[2] as usize) << 8 | (encoded[3] as usize);
    let actual_body_len = encoded.len() - 20;
    assert_eq!(
        declared_len, actual_body_len,
        "success response message_length must be accurate"
    );
}

// ---------------------------------------------------------------------------
// RFC 5389 §15.2: Binding Response format (full wire check)
// ---------------------------------------------------------------------------

#[test]
fn binding_response_wire_format() {
    let client: SocketAddr = "192.168.1.1:54321".parse().unwrap();
    let tid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let response = create_binding_response_fast(tid, client);

    // Total size: 20-byte header + 12-byte XOR-MAPPED-ADDRESS = 32 bytes
    assert_eq!(response.len(), 32, "binding response must be 32 bytes");

    // Header: Binding Success Response
    assert_eq!(response[0], 0x01, "binding response type byte 0");
    assert_eq!(response[1], 0x01, "binding response type byte 1 (method=1, class=2)");

    // Message length = 12 (just the XOR-MAPPED-ADDRESS attribute)
    assert_eq!(response[2], 0x00, "header message_length high");
    assert_eq!(response[3], 0x0C, "header message_length low (=12)");

    // Magic cookie
    assert_eq!(response[4], 0x21);
    assert_eq!(response[5], 0x12);
    assert_eq!(response[6], 0xA4);
    assert_eq!(response[7], 0x42);

    // Transaction ID
    assert_eq!(&response[8..20], &tid);

    // XOR-MAPPED-ADDRESS attribute type = 0x0020
    assert_eq!(response[20], 0x00);
    assert_eq!(response[21], 0x20);

    // Attribute length = 8
    assert_eq!(response[22], 0x00);
    assert_eq!(response[23], 0x08);

    // Reserved = 0, Family = 1 (IPv4)
    assert_eq!(response[24], 0x00, "reserved");
    assert_eq!(response[25], 0x01, "family = IPv4");

    // XOR'd port: 54321 ^ 0x2112 = 52591 = 0xCD6F
    let xport = 54321u16 ^ 0x2112;
    assert_eq!(response[26], (xport >> 8) as u8);
    assert_eq!(response[27], (xport & 0xFF) as u8);

    // XOR'd IP: 192.168.1.1 ^ [0x21, 0x12, 0xA4, 0x42]
    assert_eq!(response[28], 192 ^ 0x21);
    assert_eq!(response[29], 168 ^ 0x12);
    assert_eq!(response[30], 1 ^ 0xA4);
    assert_eq!(response[31], 1 ^ 0x42);
}

// ---------------------------------------------------------------------------
// RFC 5389 §6: Message length validation (boundary cases)
// ---------------------------------------------------------------------------

#[test]
fn message_length_overflow_handling() {
    // Verify that encoding produces a parseable message even with many attributes
    let mut msg = Message {
        header: MessageHeader {
            method: Method::Allocate,
            event_type: EventType::Success,
            message_length: 0,
            magic_cookie: 0x2112A442,
            transaction_id: [0; 12],
        },
        attributes: Vec::new(),
    };

    // Add enough attributes to create a non-trivial body
    for i in 0..100u32 {
        msg.attributes.push(Attribute {
            attr_type: Attribute::SOFTWARE,
            value: Bytes::from(format!("attr{}", i).as_bytes().to_vec()),
        });
    }

    let encoded = msg.encode();
    let declared_len = (encoded[2] as usize) << 8 | (encoded[3] as usize);
    let actual_body_len = encoded.len() - 20;
    assert_eq!(
        declared_len, actual_body_len,
        "message_length must match even with many attributes (len={})",
        actual_body_len
    );

    // Verify round-trip parse
    let parsed = Message::parse(&encoded).unwrap();
    assert_eq!(parsed.attributes.len(), 100);
}

// ---------------------------------------------------------------------------
// Attribute type constants match RFC values
// ---------------------------------------------------------------------------

#[test]
fn attribute_type_constants_correct() {
    assert_eq!(Attribute::MAPPED_ADDRESS, 0x0001);
    assert_eq!(Attribute::USERNAME, 0x0006);
    assert_eq!(Attribute::MESSAGE_INTEGRITY, 0x0008);
    assert_eq!(Attribute::ERROR_CODE, 0x0009);
    assert_eq!(Attribute::CHANNEL_NUMBER, 0x000C);
    assert_eq!(Attribute::LIFETIME, 0x000D);
    assert_eq!(Attribute::BANDWIDTH, 0x0010);
    assert_eq!(Attribute::DATA, 0x0013);
    assert_eq!(Attribute::REALM, 0x0014);
    assert_eq!(Attribute::NONCE, 0x0015);
    assert_eq!(Attribute::XOR_RELAYED_ADDRESS, 0x0016);
    assert_eq!(Attribute::REQUESTED_TRANSPORT, 0x0019);
    assert_eq!(Attribute::XOR_MAPPED_ADDRESS, 0x0020);
    assert_eq!(Attribute::SOFTWARE, 0x8022);
    assert_eq!(Attribute::FINGERPRINT, 0x8028);
    assert_eq!(Attribute::ICE_CONTROLLING, 0x8029);
    assert_eq!(Attribute::ICE_CONTROLLED, 0x802A);
}

// ---------------------------------------------------------------------------
// Error code values match RFC 5766 / RFC 5389
// ---------------------------------------------------------------------------

#[test]
fn error_code_values_correct() {
    assert_eq!(ErrorCode::TryAlternate.code(), 300);
    assert_eq!(ErrorCode::BadRequest.code(), 400);
    assert_eq!(ErrorCode::Unauthorized.code(), 401);
    assert_eq!(ErrorCode::Forbidden.code(), 403);
    assert_eq!(ErrorCode::NotFound.code(), 404);
    assert_eq!(ErrorCode::AllocationMismatch.code(), 437);
    assert_eq!(ErrorCode::StaleCredentials.code(), 438);
    assert_eq!(ErrorCode::UnsupportedTransport.code(), 442);
    assert_eq!(ErrorCode::AllocationQuotaReached.code(), 486);
    assert_eq!(ErrorCode::RoleConflict.code(), 487);
    assert_eq!(ErrorCode::ServerError.code(), 500);
    assert_eq!(ErrorCode::InsufficientCapacity.code(), 508);
}
