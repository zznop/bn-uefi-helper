# bn-uefi-helper ![Python Lint](https://github.com/zznop/bn-uefi-helper/workflows/pylint/badge.svg)

## Description

Helper plugin for analyzing UEFI firmware. This plugin contains the following features:

* Apply the correct prototype to the entry point function
* Fix segments so all segments are RWX and have the correct semantics
   * This allows for global function pointers to be rendered correctly
* Apply types for core UEFI services (from EDK-II)
* Locate known protocol GUIDs and assign the GUID type and a symbol
* Locate global assigments in entry and initialization functions and assign types
   * `EFI_SYSTEM_TABLE`, `EFI_RUNTIME_SERVICES`, `EFI_BOOT_SERVICES`, etc...
* Loader for Terse Executables

![demo bn-uefi-helper](screen.gif)

## Minimum Version

Tested on 2.3.2660

## License

This plugin is released under a MIT license.

## Related Projects

* [ghidra-firmware-utils](https://github.com/al3xtjames/ghidra-firmware-utils)
* [efiXplorer](https://github.com/binarly-io/efiXplorer)
