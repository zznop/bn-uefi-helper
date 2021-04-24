"""
Binary Ninja plugin that aids in analysis of UEFI PEI and DXE modules
"""

import os
import csv
import glob
import uuid
from binaryninja import (PluginCommand, BackgroundTaskThread, SegmentFlag, SectionSemantics, BinaryReader, Symbol,
                         SymbolType, HighLevelILOperation, BinaryView)
from binaryninja.highlevelil import HighLevelILInstruction

class UEFIHelper(BackgroundTaskThread):
    """Class for analyzing UEFI firmware to automate GUID annotation, segment fixup, type imports, and more
    """

    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(self, '', False)
        self.bv = bv
        self.br = BinaryReader(self.bv)
        self.dirname = os.path.dirname(os.path.abspath(__file__))
        self.guids = self._load_guids()

    def _fix_segments(self):
        """UEFI modules run during boot, without page protections. Everything is RWX despite that the PE is built with
        the segments not being writable. It needs to be RWX so calls through global function pointers are displayed
        properly.
        """

        for seg in self.bv.segments:
            # Make segment RWX
            self.bv.add_user_segment(seg.start, seg.data_length, seg.data_offset, seg.data_length,
                                     SegmentFlag.SegmentWritable|SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

            # Make section semantics ReadWriteDataSectionSemantics
            for section in self.bv.get_sections_at(seg.start):
                self.bv.add_user_section(section.name, section.end-section.start, SectionSemantics.ReadWriteDataSectionSemantics)

    def _import_types_from_headers(self):
        """Parse EDKII types from header files
        """

        hdrs_path = os.path.join(self.dirname, 'headers')
        headers = glob.glob(os.path.join(hdrs_path, '*.h'))
        for hdr in headers:
            _types = self.bv.platform.parse_types_from_source_file(hdr)
            for name, _type in _types.types.items():
                self.bv.define_user_type(name, _type)

    def _set_entry_point_prototype(self):
        """Apply correct prototype to the module entry point
        """

        _start = self.bv.get_function_at(self.bv.entry_point)
        _start.function_type = "EFI_STATUS ModuleEntryPoint(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)"

    def _load_guids(self):
        """Read known GUIDs from CSV and convert string GUIDs to bytes

        :return: Dictionary containing GUID bytes and associated names
        """

        guids_path = os.path.join(self.dirname, 'guids.csv')
        with open(guids_path) as f:
            reader = csv.reader(f, skipinitialspace=True)
            guids = dict(reader)

        # Convert to bytes for faster lookup
        guid_bytes = dict()
        for guid, name in guids.items():
            guid_bytes[name] = uuid.UUID(guid).bytes_le

        return guid_bytes

    def _apply_guid_name_if_data(self, name: str, address: int):
        """Check if there is a function at the address. If not, then apply the EFI_GUID type and name it

        :param name: Name/symbol to apply to the GUID
        :param address: Address of the GUID
        """

        print(f'Found {name} at 0x{hex(address)} ({uuid.UUID(bytes_le=self.guids[name])})')

        # Just to avoid a unlikely false positive and screwing up disassembly
        if self.bv.get_functions_at(address) != []:
            print(f'There is code at {address}, not applying GUID type and name')
            return

        self.bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, 'g'+name))
        t = self.bv.parse_type_string("EFI_GUID")
        self.bv.define_user_data_var(address, t[0])

    def _find_known_guids(self):
        """Search for known GUIDs and apply names to matches not within a function
        """

        names_list = list(self.guids.keys())
        guids_list = list(self.guids.values())
        def _check_guid_and_get_name(guid):
            try:
                return names_list[guids_list.index(guid)]
            except ValueError:
                return None

        for seg in self.bv.segments:
            for i in range(seg.start, seg.end):
                self.br.seek(i)
                data = self.br.read(16)
                if not data or len(data) != 16:
                    continue

                found_name = _check_guid_and_get_name(data)
                if found_name:
                    self._apply_guid_name_if_data(found_name, i)

    def _set_if_uefi_core_type(self, instr: HighLevelILInstruction):
        """Using HLIL, scrutinize the instruction to determine if it's a move of a local variable to a global variable.
        If it is, check if the source operand type is a UEFI core type and apply the type to the destination global
        variable.

        :param instr: High level IL instruction object
        """

        if instr.operation != HighLevelILOperation.HLIL_ASSIGN:
            return

        if instr.dest.operation != HighLevelILOperation.HLIL_DEREF:
            return

        if instr.dest.src.operation != HighLevelILOperation.HLIL_CONST_PTR:
            return

        if instr.src.operation != HighLevelILOperation.HLIL_VAR:
            return

        _type = instr.src.var.type
        if len(_type.tokens) == 1 and str(_type.tokens[0]) == 'EFI_HANDLE':
            self.bv.define_user_symbol(Symbol(SymbolType.DataSymbol, instr.dest.src.constant, 'gImageHandle'))
        elif len(_type.tokens) > 2 and str(_type.tokens[2]) == 'EFI_BOOT_SERVICES':
            self.bv.define_user_symbol(Symbol(SymbolType.DataSymbol, instr.dest.src.constant, 'gBootServices'))
        elif len(_type.tokens) > 2 and str(_type.tokens[2]) == 'EFI_RUNTIME_SERVICES':
            self.bv.define_user_symbol(Symbol(SymbolType.DataSymbol, instr.dest.src.constant, 'gRuntimeServices'))
        elif len(_type.tokens) > 2 and str(_type.tokens[2]) == 'EFI_SYSTEM_TABLE':
            self.bv.define_user_symbol(Symbol(SymbolType.DataSymbol, instr.dest.src.constant, 'gSystemTable'))
        else:
            return

        self.bv.define_user_data_var(instr.dest.src.constant, instr.src.var.type)
        print(f'Applied type to global assigment: {hex(instr.dest.src.constant)}')

    def _set_global_variables(self):
        """On entry, UEFI modules usually set global variables for EFI_BOOT_SERVICES, EFI_RUNTIME_SERIVCES, and
        EFI_SYSTEM_TABLE. This function attempts to identify these assignments and apply types.
        """

        for func in self.bv.functions:
            for block in func.high_level_il:
                for instr in block:
                    self._set_if_uefi_core_type(instr)

    def run(self):
        """Run the task in the background
        """

        self.progress = "UEFI Helper: Fixing up segments, applying types, and searching for known GUIDs ..."
        self._fix_segments()
        self._import_types_from_headers()
        self._set_entry_point_prototype()
        self._find_known_guids()
        self.progress = "UEFI Helper: searching for global assignments for UEFI core services ..."
        self._set_global_variables()
        print('UEFI Helper completed successfully!')

def run_uefi_helper(bv: BinaryView):
    """Run UEFI helper utilities in the background
    """

    task = UEFIHelper(bv)
    task.start()

PluginCommand.register('UEFI Helper', 'Run UEFI Helper analysis', run_uefi_helper)
