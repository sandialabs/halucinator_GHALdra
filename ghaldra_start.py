# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

#@keybinding alt e
#@menupath Emulate.Function
#@description Emulator frontend for Ghidra
#This essentially is a script that can be run to start the plugin

'''This will start the plugin without having to manually install'''

from ghaldra_plugin import GHALdraPlugin

if __name__ == "__main__":
    tool = state.getTool()
    emulator_plugin = GHALdraPlugin(tool, True, True, True)
    tool.addPlugin(emulator_plugin)
