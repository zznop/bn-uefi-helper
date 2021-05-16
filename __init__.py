# pylint: disable=missing-docstring

from binaryninja import PluginCommand
from .helper import run_uefi_helper
from .teloader import TerseExecutableView

PluginCommand.register('UEFI Helper', 'Run UEFI Helper analysis', run_uefi_helper)
TerseExecutableView.register()
