//! SSH agent protocol implementation
//!
//! This module implements the SSH agent protocol message types defined in:
//! https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent

use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, BytesMut};

/// SSH agent message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // Request messages (client -> agent)
    /// Request list of available identities (11)
    RequestIdentities = 11,
    /// Request a signature (13)
    SignRequest = 13,
    /// Add identity - not supported in SIGIL (17)
    AddIdentity = 17,
    /// Remove identity - not supported in SIGIL (18)
    RemoveIdentity = 18,
    /// Remove all identities - not supported in SIGIL (19)
    RemoveAllIdentities = 19,
    /// Lock agent - not supported in SIGIL (22)
    Lock = 22,
    /// Unlock agent - not supported in SIGIL (23)
    Unlock = 23,
    /// Add identity with constraints - not supported in SIGIL (25)
    AddIdConstrained = 25,

    // Response messages (agent -> client)
    /// List of identities (12)
    IdentitiesAnswer = 12,
    /// Signature response (14)
    SignResponse = 14,
    /// Operation failed (5)
    Failure = 5,
    /// Operation succeeded (6)
    Success = 6,
}

impl TryFrom<u8> for MessageType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            5 => Ok(MessageType::Failure),
            6 => Ok(MessageType::Success),
            11 => Ok(MessageType::RequestIdentities),
            12 => Ok(MessageType::IdentitiesAnswer),
            13 => Ok(MessageType::SignRequest),
            14 => Ok(MessageType::SignResponse),
            17 => Ok(MessageType::AddIdentity),
            18 => Ok(MessageType::RemoveIdentity),
            19 => Ok(MessageType::RemoveAllIdentities),
            22 => Ok(MessageType::Lock),
            23 => Ok(MessageType::Unlock),
            25 => Ok(MessageType::AddIdConstrained),
            _ => Err(anyhow!("Unknown message type: {}", value)),
        }
    }
}

/// SSH agent request message
#[derive(Debug, Clone)]
pub enum Request {
    /// Request list of available identities
    RequestIdentities,
    /// Request a signature
    SignRequest {
        /// Key blob (public key)
        key_blob: Vec<u8>,
        /// Data to sign
        data: Vec<u8>,
        /// Signature flags
        flags: u32,
    },
    /// Add identity (not supported)
    AddIdentity,
    /// Remove identity (not supported)
    RemoveIdentity {
        /// Key blob to remove
        key_blob: Vec<u8>,
    },
    /// Remove all identities (not supported)
    RemoveAllIdentities,
}

/// SSH agent response message
#[derive(Debug, Clone)]
pub enum Response {
    /// List of identities
    IdentitiesAnswer(Vec<IdentityEntry>),
    /// Signature response
    SignResponse {
        /// Signature blob
        signature: Vec<u8>,
    },
    /// Operation failed
    Failure,
    /// Operation succeeded
    Success,
}

/// SSH identity entry
#[derive(Debug, Clone)]
pub struct IdentityEntry {
    /// Public key blob
    pub key_blob: Vec<u8>,
    /// Comment (e.g., "ssh/github" or "github.com")
    pub comment: String,
}

/// Parse a request message from bytes
pub fn parse_request(data: &[u8]) -> Result<Request> {
    if data.is_empty() {
        return Err(anyhow!("Empty request"));
    }

    let msg_type = MessageType::try_from(data[0])?;
    let mut cursor = BytesMut::from(&data[1..]);

    match msg_type {
        MessageType::RequestIdentities => Ok(Request::RequestIdentities),
        MessageType::SignRequest => {
            // Read key blob length and blob
            if cursor.remaining() < 4 {
                return Err(anyhow!("Truncated sign request"));
            }
            let key_len = cursor.get_u32() as usize;
            if cursor.remaining() < key_len {
                return Err(anyhow!("Truncated key blob"));
            }
            let key_blob = cursor.split_to(key_len).to_vec();

            // Read data length and data
            if cursor.remaining() < 4 {
                return Err(anyhow!("Truncated sign request (data)"));
            }
            let data_len = cursor.get_u32() as usize;
            if cursor.remaining() < data_len {
                return Err(anyhow!("Truncated data"));
            }
            let data = cursor.split_to(data_len).to_vec();

            // Read flags
            if cursor.remaining() < 4 {
                return Err(anyhow!("Truncated sign request (flags)"));
            }
            let flags = cursor.get_u32();

            Ok(Request::SignRequest {
                key_blob,
                data,
                flags,
            })
        }
        MessageType::AddIdentity => Ok(Request::AddIdentity),
        MessageType::RemoveIdentity => {
            if cursor.remaining() < 4 {
                return Err(anyhow!("Truncated remove identity request"));
            }
            let key_len = cursor.get_u32() as usize;
            if cursor.remaining() < key_len {
                return Err(anyhow!("Truncated key blob"));
            }
            let key_blob = cursor.split_to(key_len).to_vec();

            Ok(Request::RemoveIdentity { key_blob })
        }
        MessageType::RemoveAllIdentities => Ok(Request::RemoveAllIdentities),
        _ => Err(anyhow!("Unsupported message type: {:?}", msg_type)),
    }
}

/// Serialize a response message to bytes
pub fn serialize_response(response: &Response) -> Result<Vec<u8>> {
    let mut buffer = BytesMut::new();

    match response {
        Response::IdentitiesAnswer(identities) => {
            buffer.put_u8(MessageType::IdentitiesAnswer as u8);

            // Write number of identities
            buffer.put_u32(identities.len() as u32);

            // Write each identity
            for identity in identities {
                // Write key blob length and blob
                buffer.put_u32(identity.key_blob.len() as u32);
                buffer.extend_from_slice(&identity.key_blob);

                // Write comment length and comment
                let comment_bytes = identity.comment.as_bytes();
                buffer.put_u32(comment_bytes.len() as u32);
                buffer.extend_from_slice(comment_bytes);
            }
        }
        Response::SignResponse { signature } => {
            buffer.put_u8(MessageType::SignResponse as u8);

            // Write signature blob
            buffer.put_u32(signature.len() as u32);
            buffer.extend_from_slice(signature);
        }
        Response::Failure => {
            buffer.put_u8(MessageType::Failure as u8);
        }
        Response::Success => {
            buffer.put_u8(MessageType::Success as u8);
        }
    }

    Ok(buffer.to_vec())
}

/// Create a failure response
pub fn failure_response() -> Vec<u8> {
    serialize_response(&Response::Failure).unwrap()
}

/// Create a success response
pub fn success_response() -> Vec<u8> {
    serialize_response(&Response::Success).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_identities() {
        let data = vec![MessageType::RequestIdentities as u8];
        let req = parse_request(&data).unwrap();
        assert!(matches!(req, Request::RequestIdentities));
    }

    #[test]
    fn test_serialize_failure() {
        let response = failure_response();
        assert_eq!(response, vec![MessageType::Failure as u8]);
    }

    #[test]
    fn test_serialize_identities_answer() {
        let identities = vec![IdentityEntry {
            key_blob: vec![1, 2, 3, 4],
            comment: "test-key".to_string(),
        }];
        let response = serialize_response(&Response::IdentitiesAnswer(identities)).unwrap();

        assert_eq!(response[0], MessageType::IdentitiesAnswer as u8);
    }
}
