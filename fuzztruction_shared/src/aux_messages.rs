use std::{convert::TryFrom, slice};

use memoffset::offset_of;

use crate::messages::{Message, MessageType, MsgHeader};
use anyhow::anyhow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AuxStreamType {
    Invalid = 0,
    LogRecord = 1,
}

impl TryFrom<u8> for AuxStreamType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            v if v == AuxStreamType::LogRecord as u8 => Ok(AuxStreamType::LogRecord),
            _ => Err(()),
        }
    }
}

const AUX_STREAM_MESSAGE_CHUNK_SIZE: usize = 512;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct AuxStreamMessage {
    header: MsgHeader,
    stream_type: AuxStreamType,
    chunk_len: usize,
    chunk: [u8; AUX_STREAM_MESSAGE_CHUNK_SIZE],
    msgs_left: usize,
}

impl AuxStreamMessage {
    pub fn max_chunk_size() -> usize {
        AUX_STREAM_MESSAGE_CHUNK_SIZE
    }

    pub fn chunk_len(&self) -> usize {
        self.chunk_len as usize
    }

    pub fn chunk(&self) -> &[u8] {
        &self.chunk[0..self.chunk_len()]
    }

    pub fn chunk_16(&self) -> Option<&[u16]> {
        if self.chunk_len() % 2 != 0 {
            return None;
        }
        let chunk = self.chunk();
        let chunk16 =
            unsafe { slice::from_raw_parts(chunk.as_ptr() as *const u16, chunk.len() / 2) };
        Some(chunk16)
    }

    pub fn stream_type(&self) -> AuxStreamType {
        self.stream_type
    }

    pub fn msgs_left(&self) -> usize {
        self.msgs_left
    }

    pub fn new(
        stream_type: AuxStreamType,
        payload: &[u8],
        msgs_left: Option<usize>,
    ) -> AuxStreamMessage {
        assert!(payload.len() <= AUX_STREAM_MESSAGE_CHUNK_SIZE);

        let mut ret = AuxStreamMessage::default();
        ret.stream_type = stream_type;
        ret.chunk_len = payload.len();
        ret.chunk[0..payload.len()].copy_from_slice(payload);
        ret.msgs_left = msgs_left.unwrap_or(0);
        ret
    }
}

impl Default for AuxStreamMessage {
    fn default() -> Self {
        AuxStreamMessage {
            header: MsgHeader::new(MessageType::AuxStreamMessage),
            stream_type: AuxStreamType::Invalid,
            chunk_len: 0,
            chunk: [0; AUX_STREAM_MESSAGE_CHUNK_SIZE],
            msgs_left: 0,
        }
    }
}

impl Message for AuxStreamMessage {
    fn message_type() -> MessageType {
        MessageType::AuxStreamMessage
    }

    fn sanitize(&self) -> anyhow::Result<()> {
        self.header.sanitize()?;
        // Check if the actual value of `stream_type` is a valid variant of
        // `AuxStreamType`.
        let offset = offset_of!(Self, stream_type);
        let raw_val = unsafe { (self as *const Self as *const u8).offset(offset as isize) };
        let raw_val = unsafe { *raw_val };
        Ok(AuxStreamType::try_from(raw_val)
            .map(|_| ())
            .or(Err(anyhow!(
                "stream_type contains invalid enum variant: {}",
                raw_val
            )))?)
    }
}
