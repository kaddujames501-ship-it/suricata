/* Copyright (C) 2017-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// written by Victor Julien

use crate::flow::Flow;
use crate::nfs::nfs::*;
use crate::nfs::nfs2_records::*;
use crate::nfs::rpc_records::*;
use crate::nfs::types::*;
use crate::core::sc_app_layer_parser_trigger_raw_stream_inspection;

use nom7::number::streaming::be_u32;
use nom7::IResult;
use crate::direction::Direction;

impl NFSState {
    /// complete request record
    pub fn process_request_record_v2(&mut self, flow: *mut Flow, r: &RpcPacket) {
        SCLogDebug!(
            "NFSv2: REQUEST {} procedure {} ({}) blob size {}",
            r.hdr.xid,
            r.procedure,
            self.requestmap.len(),
            r.prog_data.len()
        );

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);
        let aux_file_name = Vec::new();

        if r.procedure == NFSPROC3_LOOKUP {
            match parse_nfs2_request_lookup(r.prog_data) {
                Ok((_, ar)) => {
                    xidmap.file_handle = ar.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                }
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                }
            };
        } else if r.procedure == NFSPROC3_READ {
            match parse_nfs2_request_read(r.prog_data) {
                Ok((_, read_record)) => {
                    xidmap.chunk_offset = read_record.offset as u64;
                    xidmap.file_handle = read_record.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                }
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                }
            };
        } else if r.procedure == NFSPROC3_WRITE {
            match parse_nfs2_request_write(r.prog_data) {
                Ok((_, write_record)) => {
                    // Populate xidmap with file handle for reply handler
                    xidmap.file_handle = write_record.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                    self.process_write_record_v2(flow, r, &write_record);
                }
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                }
            };
        }

        if !(r.procedure == NFSPROC3_COMMIT || // commit handled separately
             r.procedure == NFSPROC3_WRITE  || // write handled in file tx
             r.procedure == NFSPROC3_READ)
        // read handled in file tx at reply
        {
            let mut tx = self.new_tx();
            tx.xid = r.hdr.xid;
            tx.procedure = r.procedure;
            tx.request_done = true;
            tx.file_name = xidmap.file_name.to_vec();
            tx.file_handle = xidmap.file_handle.to_vec();
            tx.nfs_version = r.progver as u16;

            if r.procedure == NFSPROC3_RENAME {
                tx.type_data = Some(NFSTransactionTypeData::RENAME(aux_file_name));
            }

            tx.auth_type = r.creds_flavor;
            #[allow(clippy::single_match)]
            match r.creds {
                RpcRequestCreds::Unix(ref u) => {
                    tx.request_machine_name = u.machine_name_buf.to_vec();
                    tx.request_uid = u.uid;
                    tx.request_gid = u.gid;
                }
                _ => {}
            }
            SCLogDebug!(
                "NFSv2: TX created: ID {} XID {} PROCEDURE {}",
                tx.id,
                tx.xid,
                tx.procedure
            );
            self.transactions.push(tx);
        }

        SCLogDebug!("NFSv2: TS creating xidmap {}", r.hdr.xid);
        self.requestmap.insert(r.hdr.xid, xidmap);
    }

    pub fn process_write_record_v2<'b>(&mut self, flow: *mut Flow, r: &RpcPacket<'b>, w: &Nfs2RequestWrite<'b>) -> u32 {
        let mut fill_bytes = 0;
        let pad = w.data_count % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }

        // linux defines a max of 1mb. Allow several multiples.
        if w.data_count == 0 || w.data_count > 16777216 {
            return 0;
        }

        // For NFSv2, if data_count == total_count, it's the last chunk
        let is_last = w.data_count == w.total_count;
        let file_handle = w.handle.value.to_vec();
        let file_name = if let Some(name) = self.namemap.get(w.handle.value) {
            SCLogDebug!("WRITE name {:?}", name);
            name.to_vec()
        } else {
            SCLogDebug!("WRITE object {:?} not found", w.handle.value);
            Vec::new()
        };

        // For WRITE, each operation should have its own transaction with its own XID
        // Check if there's an existing transaction for this XID and file handle (for multi-chunk writes)
        // Otherwise create a new transaction so each WRITE gets logged separately
        let existing_tx = self.transactions.iter().find(|tx| {
            tx.is_file_tx 
            && tx.procedure == NFSPROC3_WRITE
            && tx.xid == r.hdr.xid
            && tx.file_handle == file_handle
        });

        let found = if let Some(tx) = existing_tx {
            // Found existing transaction with matching XID - reuse it (multi-chunk scenario)
            let tx_idx = self.transactions.iter().position(|t| t.id == tx.id).unwrap();
            let tx = &mut self.transactions[tx_idx];
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                filetracker_newchunk(
                    &mut tdf.file_tracker,
                    &file_name,
                    w.file_data,
                    w.offset as u64,
                    w.data_count,
                    fill_bytes as u8,
                    is_last,
                    &r.hdr.xid,
                );
                tdf.chunk_count += 1;
                if is_last {
                    tdf.file_last_xid = r.hdr.xid;
                    tx.is_last = true;
                    tx.request_done = true;
                    // For single-chunk writes, mark file as closed but wait for reply to set response_done
                    // This matches NFSv3 behavior where is_file_closed indicates all data received
                    tx.is_file_closed = true;
                    sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToServer as i32);
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        if !found {
            let tx = self.new_file_tx(&file_handle, &file_name, Direction::ToServer);
            SCLogDebug!(
                "NFSv2: WRITE REQUEST creating new transaction: ID {} XID {:04X} handle {:?}",
                tx.id,
                r.hdr.xid,
                file_handle
            );
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                filetracker_newchunk(
                    &mut tdf.file_tracker,
                    &file_name,
                    w.file_data,
                    w.offset as u64,
                    w.data_count,
                    fill_bytes as u8,
                    is_last,
                    &r.hdr.xid,
                );
                tx.procedure = NFSPROC3_WRITE;
                tx.xid = r.hdr.xid;
                tx.is_first = true;
                tx.nfs_version = r.progver as u16;
                if is_last {
                    tdf.file_last_xid = r.hdr.xid;
                    tx.is_last = true;
                    tx.request_done = true;
                    // For single-chunk writes, mark file as closed but wait for reply to set response_done
                    // This matches NFSv3 behavior where is_file_closed indicates all data received
                    tx.is_file_closed = true;
                    sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToServer as i32);
                }
                SCLogDebug!(
                    "NFSv2: WRITE REQUEST transaction created: ID {} XID {:04X} is_last {} request_done {} total_txs {}",
                    tx.id,
                    tx.xid,
                    tx.is_last,
                    tx.request_done,
                    self.transactions.len()
                );
            }
        } else {
            SCLogDebug!(
                "NFSv2: WRITE REQUEST reused existing transaction: XID {:04X}",
                r.hdr.xid
            );
        }
        // UDP chunk tracking is handled in nfs.rs for TCP connections
        SCLogDebug!(
            "NFSv2: WRITE xid {:04X} offset {} data_count {} total_count {} found {}",
            r.hdr.xid,
            w.offset,
            w.data_count,
            w.total_count,
            found
        );
        0
    }

    pub fn process_reply_record_v2(&mut self, flow: *mut Flow, r: &RpcReplyPacket, xidmap: &NFSRequestXidMap) {
        let mut nfs_status = 0;
        let resp_handle = Vec::new();

        if xidmap.procedure == NFSPROC3_READ {
            match parse_nfs2_reply_read(r.prog_data) {
                Ok((_, ref reply)) => {
                    SCLogDebug!("NFSv2: READ reply record");
                    self.process_read_record(flow, r, reply, Some(xidmap));
                    nfs_status = reply.status;
                }
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                }
            }
        } else if xidmap.procedure == NFSPROC3_WRITE {
            // For WRITE, find the file transaction and update it
            // File transactions aren't found by get_tx_by_xid, so we need to search by XID
            let stat: u32 = match be_u32(r.prog_data) as IResult<&[u8], _> {
                Ok((_, stat)) => stat,
                _ => 0,
            };
            nfs_status = stat;

            SCLogDebug!(
                "NFSv2: WRITE REPLY searching for transaction: XID {:04X} handle {:?} total_txs {}",
                r.hdr.xid,
                xidmap.file_handle,
                self.transactions.len()
            );

            // Log all WRITE transactions for debugging
            for (_idx, tx) in self.transactions.iter().enumerate() {
                if tx.is_file_tx && tx.procedure == NFSPROC3_WRITE {
                    SCLogDebug!(
                        "NFSv2: WRITE REPLY found WRITE tx: ID {} XID {:04X} handle {:?} response_done {} is_last {}",
                        tx.id,
                        tx.xid,
                        tx.file_handle,
                        tx.response_done,
                        tx.is_last
                    );
                }
            }

            // Find the WRITE file transaction by XID
            // We need to search all file transactions since get_tx_by_xid excludes file_tx
            let mut tx_idx: Option<usize> = None;
            for (idx, tx) in self.transactions.iter().enumerate() {
                if tx.is_file_tx && tx.xid == r.hdr.xid && tx.procedure == NFSPROC3_WRITE {
                    SCLogDebug!(
                        "NFSv2: WRITE REPLY matched by XID: tx[{}] ID {} XID {:04X}",
                        idx,
                        tx.id,
                        tx.xid
                    );
                    tx_idx = Some(idx);
                    break;
                }
            }
            
            // Fallback: try to find by file handle if XID search failed
            // Search directly in transactions list to avoid borrow checker issues
            if tx_idx.is_none() && !xidmap.file_handle.is_empty() {
                SCLogDebug!(
                    "NFSv2: WRITE REPLY XID match failed, trying file handle fallback for {:?}",
                    xidmap.file_handle
                );
                for (idx, tx) in self.transactions.iter().enumerate() {
                    if tx.is_file_tx 
                        && tx.procedure == NFSPROC3_WRITE
                        && tx.file_handle == xidmap.file_handle
                        && tx.is_last
                        && !tx.response_done
                    {
                        SCLogDebug!(
                            "NFSv2: WRITE REPLY matched by file handle: tx[{}] ID {} XID {:04X}",
                            idx,
                            tx.id,
                            tx.xid
                        );
                        tx_idx = Some(idx);
                        break;
                    }
                }
            }

            if let Some(idx) = tx_idx {
                let tx = &mut self.transactions[idx];
                SCLogDebug!(
                    "NFSv2: WRITE REPLY found transaction: idx {} ID {} XID {:04X} is_last {} response_done {} is_file_closed {}",
                    idx,
                    tx.id,
                    tx.xid,
                    tx.is_last,
                    tx.response_done,
                    tx.is_file_closed
                );
                
                // Update transaction flags and status - mirroring READ completion logic
                tx.tx_data.updated_tc = true;
                tx.tx_data.updated_ts = true;
                tx.rpc_response_status = r.reply_state;
                tx.nfs_response_status = nfs_status;
                
                // Update XID if it wasn't set
                if tx.xid == 0 {
                    tx.xid = r.hdr.xid;
                }
                if !xidmap.file_handle.is_empty() && tx.file_handle.is_empty() {
                    tx.file_handle = xidmap.file_handle.to_vec();
                }
                
                // Check if file tracker needs finalization (mirroring READ logic)
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    // Update file_last_xid to match the reply XID
                    tdf.file_last_xid = r.hdr.xid;
                    
                    // For WRITE, if is_last was set in request (single chunk write), close the file tracker now
                    // The file tracker needs to be explicitly closed for WRITE operations
                    if tx.is_last {
                        // This was the last chunk, close the file tracker to finalize the file
                        filetracker_close(&mut tdf.file_tracker);
                        tx.is_file_closed = true;
                        tx.response_done = true;
                        SCLogDebug!(
                            "NFSv2: WRITE REPLY closing file tracker: TX ID {} XID {:04X} is_last {} response_done {} is_file_closed {}",
                            tx.id,
                            tx.xid,
                            tx.is_last,
                            tx.response_done,
                            tx.is_file_closed
                        );
                        
                        // Trigger stream inspection for both directions like READ does
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToServer as i32);
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToClient as i32);
                    } else {
                        // Not the last chunk yet, but we got the reply
                        tx.response_done = true;
                        SCLogDebug!(
                            "NFSv2: WRITE REPLY response done (not last): TX ID {} XID {:04X} response_done {}",
                            tx.id,
                            tx.xid,
                            tx.response_done
                        );
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToClient as i32);
                    }
                } else {
                    // Not a file transaction? Just mark response done
                    tx.response_done = true;
                    sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToClient as i32);
                }
            } else {
                SCLogDebug!(
                    "NFSv2: WRITE reply transaction not found for XID {:04X} handle {:?}. Total transactions: {}",
                    r.hdr.xid,
                    xidmap.file_handle,
                    self.transactions.len()
                );
            }
        } else {
            let stat: u32 = match be_u32(r.prog_data) as IResult<&[u8], _> {
                Ok((_, stat)) => stat,
                _ => 0,
            };
            nfs_status = stat;
        }
        SCLogDebug!(
            "NFSv2: REPLY {} to procedure {} blob size {}",
            r.hdr.xid,
            xidmap.procedure,
            r.prog_data.len()
        );

        if xidmap.procedure != NFSPROC3_READ && xidmap.procedure != NFSPROC3_WRITE {
            self.mark_response_tx_done(flow, r.hdr.xid, r.reply_state, nfs_status, &resp_handle);
        }
    }
}
