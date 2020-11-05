use pcsc::{Context, Scope, ShareMode, Protocols, MAX_BUFFER_SIZE};

use byteorder::{WriteBytesExt, LittleEndian};
use std::convert::TryFrom;

mod error;

use crate::error::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
struct CommandAPDU {
    cla: u8, // Instruction class - indicates the type of command, e.g. interindustry or proprietary
    ins: u8, // Instruction code - indicates the specific command, e.g. "write data"
    p1: u8,
    p2: u8,  // Instruction parameters for the command, e.g. offset into file at which to write the data
    lc: u16,  // 0, 1 or 3 bytes. Encodes the number (Nc) of bytes of command data to follow
             // 0 bytes denotes Nc=0
             // 1 byte with a value from 1 to 255 denotes Nc with the same value
             // 3 bytes, the first of which must be 0, denotes Nc in the range 1 to 65 535 (all three bytes may not be zero)
    data: Vec<u8>, // 	Lc bytes of data
    le: u16 // Encodes the maximum number (Ne) of response bytes expected
            // 0 bytes denotes Ne=0
            // 1 byte in the range 1 to 255 denotes that value of Ne, or 0 denotes Ne=256
            // 2 bytes (if extended Lc was present in the command) in the range 1 to 65 535 denotes Ne of that value, or two zero bytes denotes 65 536
            // 3 bytes (if Lc was not present in the command), the first of which must be 0, denote Ne in the same way as two-byte Le
}

impl CommandAPDU {
    pub fn new(cla: u8, ins:u8, p1:u8, p2:u8, data:Vec<u8>, le:u16) -> Result<CommandAPDU> {

        Ok(CommandAPDU {
            cla,
            ins,
            p1,
            p2,
            lc: data.len() as u16,
            data,
            le
        })
    }
}

impl From<CommandAPDU> for Vec<u8> {
    fn from(w: CommandAPDU) -> Vec<u8> {
        let mut v: Vec<u8> = vec![];

        v.push(w.cla);
        v.push(w.ins);
        v.push(w.p1);
        v.push(w.p2);
        match w.data.len() {
            0 => { },
            1..=255 => v.push(w.data.len() as u8),
            _ => {
                v.push(0);
                v.write_u16::<LittleEndian>(w.data.len() as u16);
            },
        }
        v.extend(w.data.clone());

        match w.le {
            0 => { },
            1..=255 => v.push(w.le as u8),
            _ => {
                v.push(0);
                v.write_u16::<LittleEndian>(w.le as u16);
            },
        }
        v
    }
}

#[derive(Debug)]
struct ResponseAPDU {
    data: Vec<u8>, // Nr (at most Ne) 	Response data
    sw1: u8,
    sw2: u8 // Command processing status, e.g. 90 00 (hexadecimal) indicates success
}

impl TryFrom<&[u8]> for ResponseAPDU {
    type Error = crate::Error;

    fn try_from(rapdu: &[u8]) -> Result<Self> {
        if rapdu.len() < 2 {
            return Err(crate::Error::from(""));
        }
        Ok(ResponseAPDU {
            data: Vec::from(&rapdu[0..rapdu.len()-2]),
            sw1: rapdu[rapdu.len()-2],
            sw2: rapdu[rapdu.len()-1]
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
    let apdu2 = CommandAPDU::new(0x00, 0xa4, 0x04, 0x00, vec![0x0A, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06], 0x01)?;
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