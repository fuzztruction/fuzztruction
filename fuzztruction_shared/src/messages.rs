//! This Module defines Messages that can be send or received by the coordinator.
//! There is another implementation of theses messages in C that is used by the
//! source to create and parse messages.
//!
//! NOTE: Keep the stuff implemented here in sync with the C implementation of
//! this message protocol.

use std::convert::TryFrom;

use std::mem;
use std::num::NonZeroU64;
use std::ptr;
use std::slice;

use anyhow::{anyhow, Result};

use crate::types::PatchPointID;

/// IDs of the different messages that can be send or received.
/// NOTE: Keep in sync with C code base.
#[derive(Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
pub enum MessageType {
    MsgIdInvalid = 0,
    MsgIdHello = 1,
    MsgIdRun = 2,
    MsgIdTerminated = 4,
    MsgIdShutdown = 5,
    MsgIdOk = 6,
    MsgIdTracePointStat = 10,
    MsgIdSyncMutations = 12,
    KeepAlive = 14,
    ChildPid = 15,
    AuxStreamMessage = 16,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::MsgIdInvalid
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let ret = match value {
            x if x == MessageType::MsgIdInvalid as u8 => MessageType::MsgIdInvalid,
            x if x == MessageType::MsgIdHello as u8 => MessageType::MsgIdHello,
            x if x == MessageType::MsgIdRun as u8 => MessageType::MsgIdRun,
            x if x == MessageType::MsgIdTerminated as u8 => MessageType::MsgIdTerminated,
            x if x == MessageType::MsgIdShutdown as u8 => MessageType::MsgIdShutdown,
            x if x == MessageType::MsgIdOk as u8 => MessageType::MsgIdOk,
            x if x == MessageType::MsgIdTracePointStat as u8 => MessageType::MsgIdTracePointStat,
            x if x == MessageType::MsgIdSyncMutations as u8 => MessageType::MsgIdSyncMutations,
            x if x == MessageType::KeepAlive as u8 => MessageType::KeepAlive,
            x if x == MessageType::ChildPid as u8 => MessageType::ChildPid,
            x if x == MessageType::AuxStreamMessage as u8 => MessageType::AuxStreamMessage,
            _ => return Err(()),
        };
        Ok(ret)
    }
}

/// Common operations for messages.
pub trait Message: Default {
    /// Get an instance of the message.
    fn new() -> Self
    where
        Self: Sized + Default,
    {
        Self::default()
    }

    /// Check whether all data fields are valid in the sense of not causing undefined behavior
    /// by violating rust rules. Currently, the following checks must be implemented:
    /// Enum: Check whether the raw value backing a enum variant actually represents
    ///       a valid choice for a given enum.1
    fn sanitize(&self) -> Result<()>;

    fn message_type() -> MessageType;

    /// The size of this message in bytes.
    fn size() -> usize {
        mem::size_of::<Self>()
    }

    /// Check wether it is safe to use from_byte_* to convert the given bytes
    /// to this message type.
    fn is_instance_of(bytes: &[u8]) -> bool {
        debug_assert!(Self::size() >= MsgHeader::size());

        if bytes.len() < Self::size() {
            return false;
        }

        let header = MsgHeader::from_bytes_unchecked(bytes);
        let id = <Self as Message>::message_type();
        header.id == id
    }

    /// Create a message from received bytes. This function panics if the provided
    /// slice is too small to contain a message of type Self. However, it is not
    /// checked whether the message header contains the correct ID and is in fact
    /// of type Self. This functionality is need to peek into received bytes stream
    /// for identifying the actual message type before parsing the whole message.
    fn from_bytes_unchecked(bytes: &[u8]) -> Self
    where
        Self: Sized,
    {
        debug_assert!(Self::size() >= MsgHeader::size());

        if bytes.len() < Self::size() {
            panic!(
                "Buffer is too small to contain the message: {} < {}",
                bytes.len(),
                Self::size()
            );
        }

        unsafe { ptr::read(bytes.as_ptr() as *const Self) }
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        debug_assert!(Self::size() >= MsgHeader::size());

        if bytes.len() < Self::size() {
            return Err(anyhow!(
                "Provided buffer is too small so contain this message."
            ))?;
        }

        let header = MsgHeader::from_bytes_unchecked(bytes);
        header.sanitize()?;

        let id = <Self as Message>::message_type();
        if id != header.id {
            return Err(anyhow!(
                "Unexpected message ID: expected {:#?} != {:#?} ",
                id,
                header.id
            ))?;
        }

        let ret = unsafe { ptr::read(bytes.as_ptr() as *const Self) };
        // sanitize remaining field of the struct.
        ret.sanitize()?;
        Ok(ret)
    }

    /// Get a slice that represents the raw bytes of this message.
    fn to_bytes(&self) -> &[u8]
    where
        Self: Sized + Default,
    {
        unsafe { slice::from_raw_parts(self as *const Self as *const u8, Self::size()) }
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct MsgHeader {
    pub id: MessageType,
}

impl MsgHeader {
    pub fn new(id: MessageType) -> Self {
        MsgHeader { id }
    }
}

impl Default for MsgHeader {
    fn default() -> Self {
        MsgHeader {
            id: MessageType::MsgIdInvalid,
        }
    }
}

impl Message for MsgHeader {
    fn message_type() -> MessageType {
        MessageType::MsgIdInvalid
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        if bytes.len() < Self::size() {
            return Err(anyhow!("To few bytes to contain a header"))?;
        }

        /*
        The MsgHeader type is used to peek into a byte streams
        to identify the received message. Thus we omit the message type check
        since the MsgHeader has no message type on its own .
        */
        let ret = Self::from_bytes_unchecked(bytes);
        ret.sanitize()?;

        Ok(ret)
    }

    fn sanitize(&self) -> Result<()> {
        MessageType::try_from(self.id as u8).or(Err(anyhow!(
            "Failed to convert '{}' to MessageType",
            self.id as u8
        )))?;
        Ok(())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct HelloMessage {
    header: MsgHeader,
    pub senders_tid: i32,
}

impl HelloMessage {
    pub fn new(senders_tid: i32) -> HelloMessage {
        HelloMessage {
            senders_tid,
            ..Default::default()
        }
    }
}

impl Default for HelloMessage {
    fn default() -> Self {
        HelloMessage {
            header: MsgHeader {
                id: MessageType::MsgIdHello,
            },
            senders_tid: -1,
        }
    }
}

impl Message for HelloMessage {
    fn message_type() -> MessageType {
        MessageType::MsgIdHello
    }

    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct RunMessage {
    header: MsgHeader,
    pub timeout_ms: u32,
}
impl Default for RunMessage {
    fn default() -> Self {
        RunMessage {
            header: MsgHeader::new(MessageType::MsgIdRun),
            timeout_ms: 1000,
        }
    }
}
impl RunMessage {
    pub fn from_millis(timeout_ms: u32) -> RunMessage {
        let mut msg = RunMessage::default();
        msg.timeout_ms = timeout_ms;
        msg
    }
}
impl Message for RunMessage {
    fn message_type() -> MessageType {
        MessageType::MsgIdRun
    }

    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct TerminatedMessage {
    header: MsgHeader,
    pub exit_code: i32,
    pub is_timeout: bool,
}
impl Default for TerminatedMessage {
    fn default() -> Self {
        TerminatedMessage {
            header: MsgHeader::new(MessageType::MsgIdTerminated),
            exit_code: 0,
            is_timeout: false,
        }
    }
}
impl Message for TerminatedMessage {
    fn message_type() -> MessageType {
        MessageType::MsgIdTerminated
    }

    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ShutdownMessage {
    header: MsgHeader,
}
impl Default for ShutdownMessage {
    fn default() -> Self {
        ShutdownMessage {
            header: MsgHeader::new(MessageType::MsgIdShutdown),
        }
    }
}
impl Message for ShutdownMessage {
    fn message_type() -> MessageType {
        MessageType::MsgIdShutdown
    }

    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct TracePointStat {
    header: MsgHeader,
    pub patch_point_id: PatchPointID,
    pub cnt: u64,
    pub execution_index: Option<NonZeroU64>,
}

impl TracePointStat {
    pub fn new(
        patch_point_id: PatchPointID,
        cnt: u64,
        execution_index: Option<NonZeroU64>,
    ) -> TracePointStat {
        TracePointStat {
            patch_point_id,
            cnt,
            execution_index,
            ..Default::default()
        }
    }
}

impl Default for TracePointStat {
    fn default() -> Self {
        TracePointStat {
            header: MsgHeader::new(MessageType::MsgIdTracePointStat),
            patch_point_id: PatchPointID::invalid(),
            execution_index: None,
            cnt: 0,
        }
    }
}
impl Message for TracePointStat {
    fn message_type() -> MessageType {
        MessageType::MsgIdTracePointStat
    }
    fn sanitize(&self) -> Result<()> {
        self.header.sanitize()?;
        Ok(())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct SyncMutations {
    header: MsgHeader,
}
impl SyncMutations {
    pub fn new() -> Self {
        SyncMutations {
            ..Default::default()
        }
    }
}

impl Default for SyncMutations {
    fn default() -> Self {
        SyncMutations {
            header: MsgHeader::new(MessageType::MsgIdSyncMutations),
        }
    }
}
impl Message for SyncMutations {
    fn message_type() -> MessageType {
        MessageType::MsgIdSyncMutations
    }
    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct KeepAlive {
    header: MsgHeader,
}
impl KeepAlive {
    pub fn new() -> Self {
        KeepAlive {
            ..Default::default()
        }
    }
}

impl Default for KeepAlive {
    fn default() -> Self {
        KeepAlive {
            header: MsgHeader::new(MessageType::KeepAlive),
        }
    }
}
impl Message for KeepAlive {
    fn message_type() -> MessageType {
        MessageType::KeepAlive
    }
    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Ok {
    header: MsgHeader,
}
impl Ok {
    pub fn new() -> Self {
        Ok {
            ..Default::default()
        }
    }
}

impl Default for Ok {
    fn default() -> Self {
        Ok {
            header: MsgHeader::new(MessageType::MsgIdOk),
        }
    }
}
impl Message for Ok {
    fn message_type() -> MessageType {
        MessageType::MsgIdOk
    }
    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ChildPid {
    header: MsgHeader,
    pub pid: u64,
}

impl ChildPid {
    pub fn new(pid: u64) -> Self {
        ChildPid {
            pid,
            ..Default::default()
        }
    }
}

impl Default for ChildPid {
    fn default() -> Self {
        ChildPid {
            header: MsgHeader::new(MessageType::ChildPid),
            pid: 0,
        }
    }
}
impl Message for ChildPid {
    fn message_type() -> MessageType {
        MessageType::ChildPid
    }
    fn sanitize(&self) -> Result<()> {
        Ok(self.header.sanitize()?)
    }
}

#[derive(Debug)]
pub enum ReceivableMessages {
    HelloMessage(HelloMessage),
    RunMessage(RunMessage),
    TerminatedMessage(TerminatedMessage),
    ShutdownMessage(ShutdownMessage),
    TracePointStat(TracePointStat),
    SyncMutations(SyncMutations),
    Ok(Ok),
    ChildPid(ChildPid),
}

#[cfg(test)]
mod test {

    #[test]
    fn test() {}
}
