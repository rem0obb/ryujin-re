from ida_domain import Database
from ida_domain.bytes import ByteFlags
from ida_domain.database import IdaCommandOptions
from dataclasses import dataclass
from typing import Optional
import idaapi

@dataclass
class Config:
    nops_control: int
    file_database: Optional[str] = None
    target_function_ea: Optional[int] = None

class Ryujin:
    def __init__(self, config: Config):
        self.config = config
        self.db = None
        if self.config.file_database is None:
            self.db = Database()
        else:
            self.ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
            self.db = Database.open(self.config.file_database, save_on_close=True)
        
        self.segments = self.db.segments
        self.instructions = self.db.instructions
        self.heads = self.db.heads
        self.bytes = self.db.bytes
        self.functions = self.db.functions
        self.hides = []
        self.junk_len = 0
        self.nop_start = None
       
    def __del__(self):
        if self.db:
            self.db.close(True)

    def log(self, msg):
        print(f">>> Ryujin {msg}")
    
    def is_vm_ryujin(self) -> bool:
        for seg in self.segments.get_all():
            seg_name = self.segments.get_name(seg)
            if seg_name == ".Ryujin":
                return True
        return False

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

            real_instructions = self.find_real_instructions(start_ea, end_ea)
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
