import ida_idaapi
import ida_kernwin
import ida_funcs
from ryujin import *

class UI_Hooks(ida_kernwin.UI_Hooks):
    def popup(self, ph):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            ida_kernwin.attach_dynamic_menu(ph, "Ryujin/Clean Current Function", self.clean_current)

    def clean_current(self):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        
        if func is None:
            print(">>> Ryujin No function under cursor.")
            return
        
        config = Config(nops_control=5, file_database=None, target_function_ea=func.start_ea)
        ryujin = Ryujin(config)
        ryujin.remove_junkcode()
        print(">>> Ryujin Junk code removed completed for current function.")


class RyujinPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self.hooks = UI_Hooks()
        self.hooks.hook()
        print(">>> Ryujin Plugin: Initialized. Right-click on functions to clean.")

    def run(self, arg):
        self.hooks.clean_current()

    def __del__(self):
        self.hooks.unhook()
        print(">>> Ryujin Plugin: Terminated.")


class RyujinPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI 
    comment = "Ryujin RE"
    help = "Remove junk code from Ryujin Protector binaries. Right-click on a function for single-function cleaning."
    wanted_name = "Ryujin Cleaner"
    wanted_hotkey = "Shift-R"

    def init(self):
        return RyujinPlugmod() 


def PLUGIN_ENTRY():
    return RyujinPlugin()
