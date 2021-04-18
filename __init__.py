import os
import csv
import glob
import uuid
from binaryninja import (PluginCommand, BackgroundTaskThread, SegmentFlag, SectionSemantics,
                         BinaryReader, Symbol, SymbolType)

class UEFIHelper(BackgroundTaskThread):
    """Class for analyzing UEFI firmware to automate GUID annotation, segment fixup, type imports, and more
    """

    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, 'Running UEFI helper...', False)
        self.bv = bv
        self.br = BinaryReader(self.bv)
        self.dirname = os.path.dirname(os.path.abspath(__file__))
        self.guids = self._load_guids()

    def _fix_text_segment(self):
        """UEFI modules run during boot, without page protections. Everything is RWX despite that the PE is built with
        the segments as RX. It needs to be RWX so calls through global function pointers are displayed properly.
        """

        for seg in self.bv.segments:
            if not seg.executable:
                continue

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

    def _apply_guid_name_if_data(self, name, address):
        """Check if there is a function at the address. If not, then apply the EFI_GUID type and name it

        :param name: Name/symbol to apply to the GUID
        :param address: Address of the GUID
        """

        print(f'Found {name} at 0x{hex(address)} ({uuid.UUID(bytes_le=self.guids[name])})')

        # Just to avoid a unlikely false positive and screwing up disassembly
        if self.bv.get_functions_at(address) != []:
            print(f'There is code at {address}, not applying GUID type and name')
            return
        
        self.bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, address, 'g'+name))
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

    def run(self):
        """Run the task in the background
        """

        self._fix_text_segment()
        self._import_types_from_headers()
        self._set_entry_point_prototype()
        self._find_known_guids()

def run_uefi_helper(bv):
    """Run UEFI helper utilities in the background
    """

    task = UEFIHelper(bv)
    task.start()

PluginCommand.register('UEFI Helper', 'Run UEFI Helper analysis', run_uefi_helper)
