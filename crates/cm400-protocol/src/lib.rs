//! CM400 USB protocol layer. Pure, platform-agnostic.
//!
//! The safety whitelist lives HERE, at the bottom, so no upper layer can widen
//! it. The only constructors exposed produce by-construction-valid motor
//! requests; anything else is rejected by `validate`.
//!
//! Facts encoded from spec + W0 (real device 0603:8612):
//! - wIndex = (entity << 8) | interface_number; firmware REQUIRES interface byte = 0
//!   (W0-A: A1/0x0502 STALLs).
//! - Motor = Extension Unit entity 0x05, selector 4, value 1 (up) / 2 (down).
//! - selector 5 FORBIDDEN (69 ms device reset); entity 0x03 (0x0300) FORBIDDEN
//!   (firmware hang, needs physical power cycle); wIndex 0x0000 FORBIDDEN (EP0 death).
//! - Windows reaches the XU via device-recipient (0x20/0xA0) because WinUSB rewrites
//!   the interface byte for interface-recipient; the logical request is identical.

pub const VID: u16 = 0x0603;
pub const PID: u16 = 0x8612;

/// VideoControl entities the firmware answers. Everything else is dead or poison.
pub const ENTITY_CT: u8 = 0x01;
pub const ENTITY_PU: u8 = 0x04;
pub const ENTITY_XU: u8 = 0x05;

/// Motor lives on the Extension Unit, selector 4. Selector 5 is FORBIDDEN.
pub const MOTOR_SELECTOR: u8 = 0x04;
pub const MOTOR_UP: u8 = 1;
pub const MOTOR_DOWN: u8 = 2;

/// `guidExtensionCode` of that Extension Unit, as declared in the device's VideoStreaming
/// descriptor and as DirectShow addresses it. Written uppercase-hex; a standard GUID string, so
/// `Guid::from`/`GUID.Parse` accept it byte-identically on either endianness split.
pub const MOTOR_XU_GUID: &str = "C987A729-59D3-4569-8467-FF0849FC19E8";

/// The same GUID in the 128-bit layout Windows puts in memory (Data1 in the high bits, Data4 in
/// byte order at the low end), for callers that need the value rather than the text form. A test
/// pins it against `MOTOR_XU_GUID` so the two spellings cannot drift apart - which matters because
/// a GUID typed wrongly in text form once cost a whole debugging round.
pub const MOTOR_XU_GUID_U128: u128 = 0xC987_A729_59D3_4569_8467_FF08_49FC_19E8;

/// The same control reached through `IKsControl::KsProperty` on the video capture filter, which
/// is how a Windows client that never binds our WinUSB driver can still move the lens. Measured
/// on this device and system (2026-10-12, 3/3 extend+retract with no streaming graph built): the
/// property carries the XU GUID above, the node id is the selector, and the GET/SET type flag is
/// OR'd with `KSPROPERTY_TYPE_TOPOLOGY`. What has NOT been measured: behaviour of any other flag
/// combination, so no claim is made about what omitting TOPOLOGY would return.
pub const KSPROPERTY_TYPE_GET: u32 = 0x0000_0001;
pub const KSPROPERTY_TYPE_SET: u32 = 0x0000_0002;
pub const KSPROPERTY_TYPE_TOPOLOGY: u32 = 0x0100_0000;

/// Node id inside the topology property set, i.e. `KSPROPERTY_Set.NodeId`. It is a *KS node*
/// number, not a UVC control selector: the two only happen to both be 4 on this device, and
/// defining one in terms of the other would silently move the DirectShow address whenever the
/// USB-side selector is revisited. Both are asserted separately below.
pub const MOTOR_KS_NODE_ID: u8 = 0x04;

/// Length passed as `PropertyLength` by the verified call. The `KSPROPERTY` header itself is 24
/// bytes of fields (set GUID 16 + NodeId 4 + Flags 4); the working invocation allocated and
/// passed 32, and the surplus is zeroed. Recorded as measured, not as what the struct requires:
/// nobody has tested whether 24 is accepted, so do not "optimise" this without re-running the
/// device test.
pub const MOTOR_KS_PROPERTY_HEADER_BYTES: u32 = 32;
/// Bytes of *switch data* written by SET_CUR: one byte holding 1 or 2. This is the DataLength
/// argument, a different parameter from the header size above.
pub const MOTOR_KS_SET_DATA_BYTES: u32 = 1;
/// Buffer offered for a GET_CUR read-back. The device fills one byte; the verified call passed
/// an 8-byte buffer, and `BytesReturned` says how much came back.
pub const MOTOR_KS_GET_BUFFER_BYTES: u32 = 8;

/// UVC class request codes.
pub const SET_CUR: u8 = 0x01;
pub const GET_CUR: u8 = 0x81;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    Device,
    Interface,
}

/// A logical UVC class control request. Built only via the motor constructors
/// below; `validate` is the single choke point the transports call before wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRequest {
    pub direction: Direction,
    pub recipient: Recipient,
    pub entity: u8,
    pub selector: u8,
    pub sub_index: u8,
    pub interface_number: u8,
    pub payload: Option<u8>,
}

/// The 8-byte SETUP packet as it appears on EP0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupPacket {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Cm400Error {
    ForbiddenEntity(u8),
    ForbiddenSelector(u8),
    ForbiddenIndex(u16),
    BadInterface(u8),
    BadValue(u8),
}

impl ControlRequest {
    /// GET_CUR of the motor XU selector (sub_index 0).
    pub fn motor_get(recipient: Recipient) -> Self {
        ControlRequest {
            direction: Direction::In,
            recipient,
            entity: ENTITY_XU,
            selector: MOTOR_SELECTOR,
            sub_index: 0,
            interface_number: 0,
            payload: None,
        }
    }

    /// SET_CUR of the motor XU selector to `value` (1 up / 2 down).
    /// sub_index 1 per spec §12.8 (wValue = 0x0401).
    pub fn motor_set(value: u8, recipient: Recipient) -> Self {
        ControlRequest {
            direction: Direction::Out,
            recipient,
            entity: ENTITY_XU,
            selector: MOTOR_SELECTOR,
            sub_index: 1,
            interface_number: 0,
            payload: Some(value),
        }
    }

    /// The single safety gate. Rejects anything outside the frozen whitelist.
    pub fn validate(&self) -> Result<(), Cm400Error> {
        if !matches!(self.entity, ENTITY_CT | ENTITY_PU | ENTITY_XU) {
            return Err(Cm400Error::ForbiddenEntity(self.entity));
        }
        // selector 5 is poison regardless of entity.
        if self.selector == 5 {
            return Err(Cm400Error::ForbiddenSelector(5));
        }
        // On the XU, only the motor selector (4) is allowed.
        if self.entity == ENTITY_XU && self.selector != MOTOR_SELECTOR {
            return Err(Cm400Error::ForbiddenSelector(self.selector));
        }
        // Firmware requires the interface byte to be 0.
        if self.interface_number != 0 {
            return Err(Cm400Error::BadInterface(self.interface_number));
        }
        // Motor payload is only up(1) / down(2).
        if self.entity == ENTITY_XU {
            if let Some(v) = self.payload {
                if v != MOTOR_UP && v != MOTOR_DOWN {
                    return Err(Cm400Error::BadValue(v));
                }
            }
        }
        // Defense in depth: never emit a poison wIndex.
        let idx = self.w_index();
        if idx == 0x0000 || idx == 0x0300 {
            return Err(Cm400Error::ForbiddenIndex(idx));
        }
        Ok(())
    }

    pub fn bm_request_type(&self) -> u8 {
        let dir = match self.direction {
            Direction::In => 0x80,
            Direction::Out => 0x00,
        };
        let typ = 0x20; // type = Class (bits 6-5 = 01)
        let rcp = match self.recipient {
            Recipient::Device => 0x00,
            Recipient::Interface => 0x01,
        };
        dir | typ | rcp
    }

    pub fn b_request(&self) -> u8 {
        match self.direction {
            Direction::In => GET_CUR,
            Direction::Out => SET_CUR,
        }
    }

    pub fn w_value(&self) -> u16 {
        ((self.selector as u16) << 8) | (self.sub_index as u16)
    }

    pub fn w_index(&self) -> u16 {
        ((self.entity as u16) << 8) | (self.interface_number as u16)
    }

    pub fn w_length(&self) -> u16 {
        1
    }

    /// Validate then produce the SETUP packet.
    pub fn to_setup(&self) -> Result<SetupPacket, Cm400Error> {
        self.validate()?;
        Ok(SetupPacket {
            bm_request_type: self.bm_request_type(),
            b_request: self.b_request(),
            w_value: self.w_value(),
            w_index: self.w_index(),
            w_length: self.w_length(),
        })
    }

    /// Data stage for OUT transfers.
    pub fn data_out(&self) -> Option<[u8; 1]> {
        self.payload.map(|v| [v])
    }
}

impl SetupPacket {
    /// 8-byte SETUP header in wire byte order (little-endian wValue/wIndex/wLength).
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.bm_request_type;
        b[1] = self.b_request;
        b[2] = (self.w_value & 0xff) as u8;
        b[3] = (self.w_value >> 8) as u8;
        b[4] = (self.w_index & 0xff) as u8;
        b[5] = (self.w_index >> 8) as u8;
        b[6] = (self.w_length & 0xff) as u8;
        b[7] = (self.w_length >> 8) as u8;
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motor_set_device_recipient_bytes() {
        let r = ControlRequest::motor_set(MOTOR_UP, Recipient::Device);
        let s = r.to_setup().unwrap();
        assert_eq!(s.bm_request_type, 0x20);
        assert_eq!(s.b_request, SET_CUR);
        assert_eq!(s.w_value, 0x0401);
        assert_eq!(s.w_index, 0x0500);
        assert_eq!(s.w_length, 1);
        assert_eq!(r.data_out(), Some([1]));
        // exact EP0 header: 20 01 01 04 00 05 01 00
        assert_eq!(
            s.to_bytes(),
            [0x20, 0x01, 0x01, 0x04, 0x00, 0x05, 0x01, 0x00]
        );
    }

    #[test]
    fn motor_get_device_recipient() {
        let s = ControlRequest::motor_get(Recipient::Device)
            .to_setup()
            .unwrap();
        assert_eq!(s.bm_request_type, 0xA0);
        assert_eq!(s.b_request, GET_CUR);
        assert_eq!(s.w_value, 0x0400);
        assert_eq!(s.w_index, 0x0500);
    }

    #[test]
    fn motor_interface_recipient_variant() {
        let s = ControlRequest::motor_set(MOTOR_DOWN, Recipient::Interface)
            .to_setup()
            .unwrap();
        assert_eq!(s.bm_request_type, 0x21);
        assert_eq!(s.w_index, 0x0500); // interface byte stays 0
    }

    #[test]
    fn rejects_bad_value() {
        let r = ControlRequest {
            payload: Some(3),
            ..ControlRequest::motor_set(MOTOR_UP, Recipient::Device)
        };
        assert_eq!(r.validate(), Err(Cm400Error::BadValue(3)));
    }

    #[test]
    fn rejects_selector5() {
        let r = ControlRequest {
            selector: 5,
            ..ControlRequest::motor_get(Recipient::Device)
        };
        assert_eq!(r.validate(), Err(Cm400Error::ForbiddenSelector(5)));
    }

    #[test]
    fn rejects_nonzero_interface_byte() {
        let r = ControlRequest {
            interface_number: 2,
            ..ControlRequest::motor_get(Recipient::Device)
        };
        assert_eq!(r.validate(), Err(Cm400Error::BadInterface(2)));
    }

    #[test]
    fn rejects_poison_entities() {
        let e3 = ControlRequest {
            entity: 0x03,
            ..ControlRequest::motor_get(Recipient::Device)
        };
        assert_eq!(e3.validate(), Err(Cm400Error::ForbiddenEntity(0x03)));
        let e0 = ControlRequest {
            entity: 0x00,
            ..ControlRequest::motor_get(Recipient::Device)
        };
        assert_eq!(e0.validate(), Err(Cm400Error::ForbiddenEntity(0x00)));
    }

    /// The XU GUID and the KsControl addressing are the same control seen from two sides. This
    /// test is the contract that keeps them from drifting apart: if the selector or the entity
    /// changes, the DirectShow-side constants have to be re-measured, not silently re-derived.
    #[test]
    fn motor_xu_guid_and_ks_addressing_agree_with_the_usb_path() {
        // The numeric and text spellings are one fact, not two that may drift.
        let hex = format!("{MOTOR_XU_GUID_U128:032x}");
        let spelled = format!(
            "{}-{}-{}-{}-{}",
            hex[0..8].to_uppercase(),
            hex[8..12].to_uppercase(),
            hex[12..16].to_uppercase(),
            hex[16..20].to_uppercase(),
            hex[20..32].to_uppercase()
        );
        assert_eq!(spelled, MOTOR_XU_GUID, "u128 and text must agree");
        // Canonical GUID text: 32 hex digits plus four hyphens, uppercase, standard grouping.
        assert_eq!(MOTOR_XU_GUID.len(), 36, "32 hex digits plus four hyphens");
        let hyphens: Vec<usize> = MOTOR_XU_GUID
            .char_indices()
            .filter(|(_, c)| *c == '-')
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hyphens, vec![8, 13, 18, 23], "standard GUID grouping");
        let hex: String = MOTOR_XU_GUID.chars().filter(|c| *c != '-').collect();
        assert_eq!(hex.len(), 32, "16 bytes of hex");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)),
            "uppercase hex, no stray characters: {hex}"
        );
        // The KS node id and the UVC selector are different concepts that currently coincide on
        // this device. Assert each value on its own so changing one cannot silently move the
        // other, and a future device with a different node id shows up as a failing test rather
        // than a passing definition.
        assert_eq!(MOTOR_SELECTOR, 0x04, "USB-side XU selector");
        assert_eq!(MOTOR_KS_NODE_ID, 0x04, "DirectShow-side KS node id");
        assert_eq!(
            MOTOR_KS_NODE_ID, MOTOR_SELECTOR,
            "measured equal on this device; each is defined independently"
        );
        // Three different lengths, deliberately not interchangeable: header, written data,
        // read buffer. Mixing them up is the classic KsProperty rejection.
        assert_eq!(MOTOR_KS_PROPERTY_HEADER_BYTES, 32);
        assert_eq!(MOTOR_KS_SET_DATA_BYTES, 1);
        assert_eq!(MOTOR_KS_GET_BUFFER_BYTES, 8);
        // Flags as measured on the device: type in the low word, TOPOLOGY in bit 24.
        assert_eq!(
            KSPROPERTY_TYPE_GET | KSPROPERTY_TYPE_TOPOLOGY,
            0x0100_0001,
            "verified get flags"
        );
        assert_eq!(
            KSPROPERTY_TYPE_SET | KSPROPERTY_TYPE_TOPOLOGY,
            0x0100_0002,
            "verified set flags"
        );
        // And the values themselves are the same two the USB path writes.
        assert_eq!((MOTOR_UP, MOTOR_DOWN), (1, 2));
    }
}
