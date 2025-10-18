from ida_domain import Database
from ida_domain.bytes import ByteFlags
from ida_domain.database import IdaCommandOptions
from dataclasses import dataclass
from typing import Optional
import idaapi
import builtins
import numpy as np
from numba import njit, prange

@dataclass
class Config:
    file_exe: Optional[str] = None

class Ryujin:
    def __init__(self, config: Config):
        self.config = config
        self.db = None
        if self.config.file_exe is None:
            self.db = Database()
        else:
            self.ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
            self.db = Database.open(self.config.file_exe, save_on_close=True)
        
        self.segments = self.db.segments
        self.instructions = self.db.instructions
        self.heads = self.db.heads
        self.bytes = self.db.bytes
        self.functions = self.db.functions
        self.nop_start = None
        self.seg_name = ".Ryujin"
        self.mask32 = 0xFFFFFFFF
        self.xor_keys_base = [
            0x77122545, 0x88998877, 0x9944DEAD, 0x10CAFEB4,
            0x45B0B0C4, 0x35DEADDE, 0x25C4C4C4, 0x85634897,
            0x56123456, 0x11454545, 0x12323232, 0x95959595 ]
        self.xor_keys_21 = np.array([np.uint32(x) for x in self.xor_keys_base], dtype=np.uint32)
      
    def __del__(self):
        if self.db:
            self.db.close(True)

    def log(self, msg):
        print(f">>> Ryujin {msg}")
    
    def is_vm_ryujin(self) -> bool:
        for seg in self.segments.get_all():
            seg_name = self.segments.get_name(seg)
            if seg_name == self.seg_name:
                return True
        return False

    @staticmethod
    @njit(parallel=True, nogil=True)
    def _process_pairs_numba_for_teadelkew(arr32, num_pairs, xorkeys12, mask32):
        key_k1 = np.uint32(0x56343698)
        key_k0 = np.uint32(0xA9BF9BAA)
        sum_init = np.uint32(0x85862000)
        delta = np.uint32(0x00B0B0C4)
 
        for i in prange(num_pairs):
            off = 2 * i
            v0 = np.uint32(arr32[off])
            v1 = np.uint32(arr32[off + 1])
 
            s = sum_init
 
            for _ in range(2048):
                part = np.uint32(((v0 << np.uint32(4)) ^ (v0 >> np.uint32(5))) & np.uint32(mask32))
                part = np.uint32((part + v0) & np.uint32(mask32))
                tmp = np.uint32((~part) & np.uint32(mask32)) ^ np.uint32((s + key_k1) & np.uint32(mask32))
                v1 = np.uint32((v1 - tmp) & np.uint32(mask32))
 
                s = np.uint32((s - delta) & np.uint32(mask32))
 
                part2 = np.uint32(((v1 << np.uint32(4)) ^ (v1 >> np.uint32(5))) & np.uint32(mask32))
                part2 = np.uint32((part2 + v1) & np.uint32(mask32))
                tmp2 = np.uint32((~part2) & np.uint32(mask32)) ^ np.uint32((s + key_k0) & np.uint32(mask32))
                v0 = np.uint32((v0 - tmp2) & np.uint32(mask32))
 
            for j in range(2048):
                key_x = xorkeys12[j % 12]
                term = np.uint32((np.uint64(j) * np.uint64(0x44444444)) & np.uint64(mask32))
                nm = np.uint32((~np.uint32(j)) & np.uint32(mask32))
                v1 = np.uint32(v1 ^ key_x ^ term ^ nm)
                v0 = np.uint32(v0 ^ key_x ^ term ^ nm)
 
            arr32[off] = np.uint32((~v0) & np.uint32(mask32))
            arr32[off + 1] = np.uint32((~v1) & np.uint32(mask32))
    
    def _execute_decrypt(self, buf: bytearray, stub_size: int = 0):
        length = len(buf)
        limit = length - stub_size
        if limit < 8:
            return 0
 
        num_pairs = limit // 8
 
        arr_full = np.frombuffer(buf, dtype=np.uint32)
        needed_elems = num_pairs * 2
 
        made_copy = False
        if arr_full.size < needed_elems:
            arr32 = np.frombuffer(bytes(buf), dtype=np.uint32).copy()
            made_copy = True
        else:
            arr32 = arr_full
 
        self._process_pairs_numba_for_teadelkew(arr32, num_pairs, self.xor_keys_21, self.mask32)
 
        if made_copy:
            buf[:arr32.nbytes] = arr32.view(np.uint8)[:arr32.nbytes]
 
        return num_pairs

    def decrypt(self):
        if self.is_vm_ryujin():
            ryujin_seg = self.segments.get_by_name(self.seg_name)
            self.log("Performing decryption on the 'Ryujin' section")
            section_opcodes = self.bytes.get_bytes_at(ryujin_seg.start_ea, ryujin_seg.end_ea-ryujin_seg.start_ea)
            data = bytearray(section_opcodes)
            blocks = self._execute_decrypt(data, stub_size=1625)
            self.bytes.set_bytes_at(ryujin_seg.start_ea, builtins.bytes(data))
 
            self.log(f"We Processed {blocks} 8-byte blocks")
        else:
            self.log("Binary not using Ryujin VM")