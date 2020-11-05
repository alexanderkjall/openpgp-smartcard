use pcsc::{Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};

use byteorder::{LittleEndian, WriteBytesExt};
use std::convert::TryFrom;

mod error;

use crate::error::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
enum INS {
    DeactivateFile = 0x04,
    DeactivateRecord = 0x06,
    ActivateRecord = 0x08,
    EraseRecord = 0x0C,
    EraseBinary = 0x0E,
    EraseBinary2 = 0x0F,
    PerformScqlOperation = 0x10,
    PerformTransactionOperation = 0x12,
    PerformUserOperation = 0x14,
    Verify = 0x20,
    Verify2 = 0x21,
    ManageSecurityEnvironment = 0x22,
    ChangeReferenceData = 0x24,
    ChangeReferenceData2 = 0x25,
    DisableVerificationRequirement = 0x26,
    EnableVerificationRequirement = 0x28,
    PerformSecurityOperation = 0x2A,
    PerformSecurityOperation2 = 0x2B,
    ResetRetryCounter = 0x2C,
    ResetRetryCounter2 = 0x2D,
    PerformBiometricOperation = 0x2E,
    PerformBiometricOperation2 = 0x2F,
    Compare = 0x33,
    GetAttribute = 0x34,
    GetAttribute2 = 0x35,
    ApplicationManagementRequest = 0x40,
    ApplicationManagementRequest2 = 0x41,
    ActivateFile = 0x44,
    GenerateAsymmetricKeyPair = 0x46,
    GenerateAsymmetricKeyPair2 = 0x47,
    ManageChannel = 0x70,
    ExternalMutualAuthenticate = 0x82,
    GetChallenge = 0x84,
    GeneralAuthenticate = 0x86,
    GeneralAuthenticate2 = 0x87,
    InternalAuthenticate = 0x88,
    SearchBinary = 0xA0,
    SearchBinary2 = 0xA1,
    SearchRecord = 0xA2,
    Select = 0xA4,
    SelectData = 0xA5,
    ReadBinary = 0xB0,
    ReadBinary2 = 0xB1,
    ReadRecord = 0xB2,
    ReadRecord2 = 0xB3,
    GetResponse = 0xC0,
    Envelope = 0xC2,
    Envelope2 = 0xC3,
    GetData = 0xCA,
    GetData2 = 0xCB,
    GetNextData = 0xCC,
    GetNextData2 = 0xCD,
    ManageData = 0xCF,
    WriteBinary = 0xD0,
    WriteBinary2 = 0xD1,
    WriteRecord = 0xD2,
    UpdateBinary = 0xD6,
    UpdateBinary2 = 0xD7,
    PutNextData = 0xD8,
    PutNextData2 = 0xD9,
    PutData = 0xDA,
    PutData2 = 0xDB,
    UpdateRecord = 0xDC,
    UpdateRecord2 = 0xDD,
    UpdateData = 0xDE,
    UpdateData2 = 0xDF,
    CreateFile = 0xE0,
    AppendRecord = 0xE2,
    DeleteFile = 0xE4,
    TerminateDf = 0xE6,
    TerminateEf = 0xE8,
    LoadApplication = 0xEA,
    LoadApplication2 = 0xEB,
    DeleteData = 0xEE,
    RemoveApplication = 0xEC,
    RemoveApplication2 = 0xED,
    TerminateCardUsage = 0xFE,
}

#[derive(Debug)]
struct CommandAPDU {
    /// Instruction class - indicates the type of command, e.g. interindustry or proprietary
    cla: u8,
    /// Instruction code - indicates the specific command, e.g. "write data"
    ins: INS,
    /// Instruction parameters for the command byte 1, e.g. offset into file at which to write the data
    p1: u8,
    /// Instruction parameters for the command byte 2, e.g. offset into file at which to write the data
    p2: u8,
    /// 0, 1 or 3 bytes. Encodes the number (Nc) of bytes of command data to follow
    /// 0 bytes denotes Nc=0
    /// 1 byte with a value from 1 to 255 denotes Nc with the same value
    /// 3 bytes, the first of which must be 0, denotes Nc in the range 1 to 65 535 (all three bytes may not be zero)
    lc: u16,
    /// 	Lc bytes of data
    data: Vec<u8>,
    /// Encodes the maximum number (Ne) of response bytes expected
    /// 0 bytes denotes Ne=0
    /// 1 byte in the range 1 to 255 denotes that value of Ne, or 0 denotes Ne=256
    /// 2 bytes (if extended Lc was present in the command) in the range 1 to 65 535 denotes Ne of that value, or two zero bytes denotes 65 536
    /// 3 bytes (if Lc was not present in the command), the first of which must be 0, denote Ne in the same way as two-byte Le
    le: u16,
}

impl CommandAPDU {
    pub fn new(cla: u8, ins: INS, p1: u8, p2: u8, data: Vec<u8>, le: u16) -> Result<CommandAPDU> {
        Ok(CommandAPDU {
            cla,
            ins,
            p1,
            p2,
            lc: data.len() as u16,
            data,
            le,
        })
    }
}

impl From<CommandAPDU> for Vec<u8> {
    fn from(w: CommandAPDU) -> Vec<u8> {
        let mut v: Vec<u8> = vec![];

        v.push(w.cla);
        v.push(w.ins as u8);
        v.push(w.p1);
        v.push(w.p2);
        match w.data.len() {
            0 => {}
            1..=255 => v.push(w.data.len() as u8),
            _ => {
                v.push(0);
                v.write_u16::<LittleEndian>(w.data.len() as u16);
            }
        }
        v.extend(w.data.clone());

        match w.le {
            0 => {}
            1..=255 => v.push(w.le as u8),
            _ => {
                v.push(0);
                v.write_u16::<LittleEndian>(w.le as u16);
            }
        }
        v
    }
}

#[derive(Debug)]
struct ResponseAPDU {
    data: Vec<u8>,
    // Nr (at most Ne) 	Response data
    sw1: u8,
    sw2: u8, // Command processing status, e.g. 90 00 (hexadecimal) indicates success
}

impl TryFrom<&[u8]> for ResponseAPDU {
    type Error = crate::Error;

    fn try_from(rapdu: &[u8]) -> Result<Self> {
        if rapdu.len() < 2 {
            return Err(crate::Error::from(""));
        }
        Ok(ResponseAPDU {
            data: Vec::from(&rapdu[0..rapdu.len() - 2]),
            sw1: rapdu[rapdu.len() - 2],
            sw2: rapdu[rapdu.len() - 1],
        })
    }
}

fn main() -> Result<()> {
    // Establish a PC/SC context.
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("Failed to establish context: {}", err);
            std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            eprintln!("Failed to list readers: {}", err);
            std::process::exit(1);
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            println!("No readers are connected.");
            return Ok(());
        }
    };
    println!("Using reader: {:?}", reader);

    // Connect to the card.
    let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
        Ok(card) => card,
        Err(pcsc::Error::NoSmartcard) => {
            println!("A smartcard is not present in the reader.");
            return Ok(());
        }
        Err(err) => {
            eprintln!("Failed to connect to card: {}", err);
            std::process::exit(1);
        }
    };

    // Send an APDU command.
    let apdu2 = CommandAPDU::new(
        0x00,
        INS::Select,
        0x04,
        0x00,
        vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01],
        0x00,
    )?;
    println!("Sending APDU: {:?}", apdu2);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = match card.transmit(&Vec::from(apdu2), &mut rapdu_buf) {
        Ok(rapdu) => ResponseAPDU::try_from(rapdu)?,
        Err(err) => {
            eprintln!("Failed to transmit APDU command to card: {}", err);
            std::process::exit(1);
        }
    };

    println!("APDU response: {:?}", rapdu);

    Ok(())
}

mod test {
    #[test]
    fn apdu() {
        let apdu = crate::CommandAPDU::new(
            0x00,
            crate::INS::Select,
            0x04,
            0x00,
            vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01],
            0x00,
        )
        .unwrap();

        assert_eq!(
            &Vec::from(apdu),
            b"\x00\xa4\x04\x00\x0A\xA0\x00\x00\x00\x62\x03\x01\x0C\x06\x01"
        );
    }
}
