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
    nops_control: int
    file_exe: Optional[str] = None
    target_function_ea: Optional[int] = None

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
        self.hides = []
        self.junk_len = 0
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

    def _hide_nops_in_range(self, start_ea, end_ea):
        self.nop_start = None
        self.junk_len = 0
    
        for head in self.heads.get_between(start_ea, end_ea):
            if self.heads.is_code(head):
                ins = self.instructions.get_at(head)
                mn = self.instructions.get_mnemonic(ins)
            
                if mn == "nop":
                    if self.nop_start is None:
                        self.nop_start = head
                    self.junk_len += 1
                else:
                    if self.junk_len >= self.config.nops_control:
                        self.hides.append((self.nop_start, self.junk_len))
                    self.nop_start = None
                    self.junk_len = 0
    
        if self.junk_len >= self.config.nops_control:
            self.hides.append((self.nop_start, self.junk_len))
        
    def _hide_nops(self, start_ea: Optional[int] = None, end_ea: Optional[int] = None):
        self.hides = []
        self.junk_len = 0
        self.nop_start = None
        
        if start_ea is None and end_ea is None:
            for seg in self.segments.get_all():
                s_start = seg.start_ea
                s_end = seg.end_ea
                  
                self.log(f"Processing NOPs in segment '{self.segments.get_name(seg)}', {hex(s_start)} - {hex(s_end)}")
                self._hide_nops_in_range(s_start, s_end)
        else:
            self.log(f"Processing NOPs in range {hex(start_ea)} - {hex(end_ea)}")
            self._hide_nops_in_range(start_ea, end_ea)
        
        for hide_start, hide_len in self.hides:
            ins = self.instructions.get_at(hide_start)
            idaapi.del_hidden_range(hide_start)
            idaapi.add_hidden_range(hide_start, hide_start+hide_len, "", "", "", 0xEEFFFF) # ida-domain does not implement hiding in memory ranges, alternative using idaapi : (
          
    def _find_real_instructions(self, start_ea, end_ea: Optional[int] = None) -> list[int]:
        real_instruction_address = []
        cur_ea = start_ea
        instr = self.instructions.get_at(cur_ea)
        
        while instr is not None and (end_ea is None or cur_ea < end_ea):
            if self.instructions.get_mnemonic(instr) == "popf":
                ea1 = cur_ea + instr.size
                instr2 = self.instructions.get_at(ea1)
                if instr2 and self.instructions.get_mnemonic(instr2) == "pop":
                    ea2 = ea1 + instr2.size
                    instr3 = self.instructions.get_at(ea2)
                    if instr3:
                        ea3 = ea2 + instr3.size
                        instr4 = self.instructions.get_at(ea3)
                        mn3 = self.instructions.get_mnemonic(instr3)
                        if instr4 and self.instructions.get_mnemonic(instr4) == "nop" and mn3 != "nop":
                            self.log(f"Real instruction at 0x{instr3.ea:x} -> {self.instructions.get_disassembly(instr3)}")
                            real_instruction_address.append(instr3.ea)
            cur_ea += instr.size
            instr = self.instructions.get_at(cur_ea)
        
        return real_instruction_address

    def _process_single_function(self, func_ea: int):
        f = self.functions.get_at(func_ea)
        if f is None:
            self.log("No function found at specified 'ea'")
            return
        start_ea = f.start_ea
        end_ea = f.end_ea
        self.log(f"Processing function {f.name} from 0x{start_ea:x} to 0x{end_ea:x}")
        real_instructions = self._find_real_instructions(start_ea, end_ea)
        self.log(f"Collected {len(real_instructions)} real instruction addresses in function {f.name}")
        valid_instructions = {}
        for ea in real_instructions:
            instr = self.instructions.get_at(ea)
            if instr:
                valid_instructions[ea] = instr
        cur_ea = start_ea
        while cur_ea < end_ea:
            if cur_ea in valid_instructions:
                self.log(f"Kept valid instruction at 0x{cur_ea:x}: {self.instructions.get_disassembly(valid_instructions[cur_ea])}")
                cur_ea += valid_instructions[cur_ea].size
            else:
                self.bytes.patch_byte_at(cur_ea, 0x90)
                cur_ea += 1

    def _process_functions(self):
        total_real_instructions = 0
        for f in self.functions:
            start_ea = f.start_ea
            end_ea = f.end_ea
            self.log(f"Processing function {f.name} from 0x{start_ea:x} to 0x{end_ea:x}")
            real_instructions = self._find_real_instructions(start_ea, end_ea)
            total_real_instructions += len(real_instructions)
            self.log(f"Collected {len(real_instructions)} real instruction addresses in function {f.name}")
            valid_instructions = {}
            for ea in real_instructions:
                instr = self.instructions.get_at(ea)
                if instr:
                    valid_instructions[ea] = instr
            cur_ea = start_ea
            while cur_ea < end_ea:
                if cur_ea in valid_instructions:
                    self.log(f"Kept valid instruction at 0x{cur_ea:x}: {self.instructions.get_disassembly(valid_instructions[cur_ea])}")
                    cur_ea += valid_instructions[cur_ea].size
                else:
                    self.bytes.patch_byte_at(cur_ea, 0x90)
                    cur_ea += 1
        self.log(f"Total real instructions found across all functions: {total_real_instructions}")
  
    def remove_junkcode(self):
        if self.is_vm_ryujin():
            if self.config.target_function_ea is not None:
                self._process_single_function(self.config.target_function_ea)
                f = self.functions.get_at(self.config.target_function_ea)
                if f:
                    self._hide_nops(f.start_ea, f.end_ea)
            else:
                self._process_functions()
                self._hide_nops()
        else:
            self.log("Binary not using Ryujin VM")

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