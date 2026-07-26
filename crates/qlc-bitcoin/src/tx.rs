// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::sha256::double_sha256;
use crate::SpvError;

pub struct TxInput {
    raw: Vec<u8>,
}

#[derive(Clone)]
pub struct TxOutput {
    pub value: u64,
    pub script: Vec<u8>,
}

pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SpvError> {
        let end = self.pos.checked_add(n).ok_or(SpvError::MalformedTransaction)?;
        if end > self.bytes.len() {
            return Err(SpvError::MalformedTransaction);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32_le(&mut self) -> Result<u32, SpvError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64_le(&mut self) -> Result<u64, SpvError> {
        let b = self.take(8)?;
        let mut w = [0u8; 8];
        w.copy_from_slice(b);
        Ok(u64::from_le_bytes(w))
    }

    fn varint(&mut self) -> Result<u64, SpvError> {
        let first = self.take(1)?[0];
        match first {
            0xff => self.u64_le(),
            0xfe => Ok(self.u32_le()? as u64),
            0xfd => {
                let b = self.take(2)?;
                Ok(u16::from_le_bytes([b[0], b[1]]) as u64)
            }
            n => Ok(n as u64),
        }
    }
}

fn put_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

const MAX_COUNT: u64 = 100_000;

impl Transaction {
    /// Parse a raw Bitcoin transaction, legacy or segwit. The txid is always taken over the
    pub fn parse(bytes: &[u8]) -> Result<Transaction, SpvError> {
        let mut c = Cursor::new(bytes);
        let version = c.u32_le()?;

        let segwit = bytes.len() >= 6 && bytes[4] == 0x00 && bytes[5] == 0x01;
        if segwit {
            c.take(2)?;
        }

        let input_count = c.varint()?;
        if input_count > MAX_COUNT {
            return Err(SpvError::MalformedTransaction);
        }
        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            let start = c.pos;
            c.take(36)?; // previous outpoint, txid plus index
            let script_len = c.varint()?;
            c.take(script_len as usize)?;
            c.take(4)?; // sequence
            inputs.push(TxInput {
                raw: bytes[start..c.pos].to_vec(),
            });
        }

        let output_count = c.varint()?;
        if output_count > MAX_COUNT {
            return Err(SpvError::MalformedTransaction);
        }
        let mut outputs = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            let value = c.u64_le()?;
            let script_len = c.varint()?;
            let script = c.take(script_len as usize)?.to_vec();
            outputs.push(TxOutput { value, script });
        }

        if segwit {
            for _ in 0..input_count {
                let items = c.varint()?;
                for _ in 0..items {
                    let len = c.varint()?;
                    c.take(len as usize)?;
                }
            }
        }

        let locktime = c.u32_le()?;

        Ok(Transaction {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    fn legacy_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        put_varint(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.raw);
        }
        put_varint(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            put_varint(&mut out, output.script.len() as u64);
            out.extend_from_slice(&output.script);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// The transaction id, double SHA-256 over the legacy serialization, the same value a
    pub fn txid(&self) -> [u8; 32] {
        double_sha256(&self.legacy_bytes())
    }

    /// The Quantova recipient carried in the single OP_RETURN output as an exact 32 byte push,
    pub fn op_return_recipient(&self) -> Option<[u8; 32]> {
        let mut found: Option<[u8; 32]> = None;
        for output in &self.outputs {
            let s = &output.script;
            if s.first() == Some(&0x6a) && s.len() == 34 && s[1] == 0x20 {
                if found.is_some() {
                    return None;
                }
                let mut r = [0u8; 32];
                r.copy_from_slice(&s[2..34]);
                found = Some(r);
            }
        }
        found
    }

    /// The total value, in satoshis, paid to the bridge deposit script across every output that
    pub fn value_to_script(&self, deposit_script: &[u8]) -> u128 {
        let mut total: u128 = 0;
        for output in &self.outputs {
            if output.script.as_slice() == deposit_script {
                total = total.saturating_add(output.value as u128);
            }
        }
        total
    }

    /// Bind a transaction to a deposit: it pays the bridge deposit script a positive amount and
    pub fn deposit_to(&self, deposit_script: &[u8]) -> Option<(u128, [u8; 32])> {
        let amount = self.value_to_script(deposit_script);
        if amount == 0 {
            return None;
        }
        let recipient = self.op_return_recipient()?;
        Some((amount, recipient))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p2pkh(hash160: [u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&hash160);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    fn op_return(recipient: [u8; 32]) -> Vec<u8> {
        let mut s = vec![0x6a, 0x20];
        s.extend_from_slice(&recipient);
        s
    }

    fn serialize_legacy(tx: &Transaction) -> Vec<u8> {
        tx.legacy_bytes()
    }

    fn build(outputs: Vec<TxOutput>) -> Transaction {
        // one dummy input, previous outpoint plus an empty script plus a sequence
        let mut raw = vec![0u8; 36];
        raw.push(0x00);
        raw.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        Transaction {
            version: 2,
            inputs: vec![TxInput { raw }],
            outputs,
            locktime: 0,
        }
    }

    #[test]
    fn a_deposit_binds_amount_and_recipient_from_the_outputs() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let tx = build(vec![
            TxOutput {
                value: 250_000,
                script: bridge.clone(),
            },
            TxOutput {
                value: 0,
                script: op_return(recipient),
            },
        ]);
        let bytes = serialize_legacy(&tx);
        let parsed = Transaction::parse(&bytes).expect("parses");
        assert_eq!(parsed.txid(), tx.txid(), "reparse reproduces the txid");
        let (amount, r) = parsed.deposit_to(&bridge).expect("is a deposit");
        assert_eq!(amount, 250_000);
        assert_eq!(r, recipient);
    }

    #[test]
    fn splitting_the_deposit_across_outputs_still_sums() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let tx = build(vec![
            TxOutput {
                value: 100_000,
                script: bridge.clone(),
            },
            TxOutput {
                value: 150_000,
                script: bridge.clone(),
            },
            TxOutput {
                value: 0,
                script: op_return(recipient),
            },
        ]);
        let bytes = serialize_legacy(&tx);
        let parsed = Transaction::parse(&bytes).expect("parses");
        let (amount, _) = parsed.deposit_to(&bridge).expect("is a deposit");
        assert_eq!(amount, 250_000, "both outputs to the bridge are summed");
    }

    #[test]
    fn a_payment_that_never_reaches_the_bridge_is_not_a_deposit() {
        let bridge = p2pkh([0x11; 20]);
        let elsewhere = p2pkh([0x22; 20]);
        let tx = build(vec![
            TxOutput {
                value: 250_000,
                script: elsewhere,
            },
            TxOutput {
                value: 0,
                script: op_return([0x42u8; 32]),
            },
        ]);
        let bytes = serialize_legacy(&tx);
        let parsed = Transaction::parse(&bytes).expect("parses");
        assert!(parsed.deposit_to(&bridge).is_none());
    }

    #[test]
    fn two_recipients_are_ambiguous_and_refused() {
        let bridge = p2pkh([0x11; 20]);
        let tx = build(vec![
            TxOutput {
                value: 250_000,
                script: bridge.clone(),
            },
            TxOutput {
                value: 0,
                script: op_return([0x42u8; 32]),
            },
            TxOutput {
                value: 0,
                script: op_return([0x43u8; 32]),
            },
        ]);
        let bytes = serialize_legacy(&tx);
        let parsed = Transaction::parse(&bytes).expect("parses");
        assert!(parsed.deposit_to(&bridge).is_none(), "two op returns name no single recipient");
    }
}
