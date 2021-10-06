# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

'''This file just defines the gui for the ghaldra plugin'''
from ghidra.framework.plugintool import ComponentProviderAdapter
from java.awt import GridBagConstraints, GridBagLayout
from javax.swing import (AbstractAction, JButton, JLabel, JPanel, JScrollPane,
                         JTextArea, JTextField)


class GHALdraInputAction(AbstractAction):
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, e):
        self.ec.plugin.do_cmd()

class GHALdraStartBtnAction(AbstractAction):
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, e):
        self.ec.plugin.do_start()

class GHALdraQuitBtnAction(AbstractAction):
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, e):
        self.ec.plugin.quit_emulator()

class GHALdraComponentProvider(ComponentProviderAdapter):
    def __init__(self, plugin):
        super(GHALdraComponentProvider, self).__init__(plugin.getTool(), "GHALdra", "emulate_function")
        self.plugin = plugin

        self.panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridy = 0

        c.gridx = 0
        c.weightx = 0.6
        self.panel_label = JLabel("")
        self.panel.add(self.panel_label, c)

        c.gridx = 1
        c.weightx = 0.2
        self.panel_btn = JButton("Start")
        self.panel_btn.addActionListener(GHALdraStartBtnAction(self))
        self.panel.add(self.panel_btn, c)

        c.gridx = 2
        c.weightx = 0.2
        self.quit_panel_btn = JButton("Quit")
        self.quit_panel_btn.addActionListener(GHALdraQuitBtnAction(self))
        self.panel.add(self.quit_panel_btn, c)

        c.gridx = 0
        c.gridy = 1
        c.gridwidth = 3
        self.panel_input = JTextField()
        self.panel_input.addActionListener(GHALdraInputAction(self))
        self.panel.add(self.panel_input, c)

        c.gridx = 0
        c.gridy = 3
        c.gridwidth = 3
        text_string = "For commands, type `h` then enter"
        self.panel_help = JLabel(text_string)
        self.panel.add(self.panel_help, c)

        c.gridx = 0
        c.gridy = 5
        c.gridwidth = 3
        text_string = "Register State when stopped"
        self.reg_help = JLabel(text_string)
        self.panel.add(self.reg_help, c)

        c.gridy = 7
        c.gridwidth = 3
        self.reg_label = JTextArea(7,7)
        self.reg_label.setBorder(None)
        self.reg_label.setEditable(False)
        self.reg_label.setBackground(None)
        self.reg_label.setOpaque(True)

        self.reg_stack_scroll = JScrollPane(self.reg_label,
                                            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                                            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self.panel.add(self.reg_stack_scroll, c)

        self.setStatus("Stopped")

    def getComponent(self):
        return self.panel

    def setStatus(self, status):
        self.panel_label.setText(status)

    def set_registers(self, registers):
        '''update the register values'''
        self.reg_label.setText(registers)
