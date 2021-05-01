from binaryninja import PluginCommand
from .helper import run_uefi_helper

PluginCommand.register('UEFI Helper', 'Run UEFI Helper analysis', run_uefi_helper)
