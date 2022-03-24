typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    word;

struct EFI_PEI_PPI_DESCRIPTOR;
struct EFI_STATUS_CODE_DATA;
struct EFI_FV_FILE_INFO;
struct EFI_FV_FILE_INFO2;
struct EFI_PEI_PCI_CFG2_PPI;
struct EFI_PEI_CPU_IO_PPI;
struct EFI_FV_INFO;

struct _EFI_PEI_SERVICES;
typedef struct _EFI_PEI_SERVICES EFI_PEI_SERVICES;

typedef UINT64 UINTN;

typedef UINTN RETURN_STATUS;

typedef RETURN_STATUS EFI_STATUS;

typedef EFI_STATUS (* EFI_PEI_INSTALL_PPI)(EFI_PEI_SERVICES * *, struct EFI_PEI_PPI_DESCRIPTOR *);

typedef EFI_STATUS (* EFI_PEI_REINSTALL_PPI)(EFI_PEI_SERVICES * *, struct EFI_PEI_PPI_DESCRIPTOR *, struct EFI_PEI_PPI_DESCRIPTOR *);

typedef GUID EFI_GUID;

typedef EFI_STATUS (* EFI_PEI_LOCATE_PPI)(EFI_PEI_SERVICES * *, EFI_GUID *, UINTN, struct EFI_PEI_PPI_DESCRIPTOR * *, void * *);

struct _EFI_PEI_NOTIFY_DESCRIPTOR;
typedef struct _EFI_PEI_NOTIFY_DESCRIPTOR EFI_PEI_NOTIFY_DESCRIPTOR;

typedef EFI_STATUS (* EFI_PEI_NOTIFY_PPI)(EFI_PEI_SERVICES * *, EFI_PEI_NOTIFY_DESCRIPTOR *);

typedef UINT32 EFI_BOOT_MODE;

typedef EFI_STATUS (* EFI_PEI_GET_BOOT_MODE)(EFI_PEI_SERVICES * *, EFI_BOOT_MODE *);

typedef EFI_STATUS (* EFI_PEI_SET_BOOT_MODE)(EFI_PEI_SERVICES * *, EFI_BOOT_MODE);

typedef EFI_STATUS (* EFI_PEI_GET_HOB_LIST)(EFI_PEI_SERVICES * *, void * *);

typedef EFI_STATUS (* EFI_PEI_CREATE_HOB)(EFI_PEI_SERVICES * *, UINT16, UINT16, void * *);

typedef void * EFI_PEI_FV_HANDLE;

typedef EFI_STATUS (* EFI_PEI_FFS_FIND_NEXT_VOLUME2)(EFI_PEI_SERVICES * *, UINTN, EFI_PEI_FV_HANDLE *);

typedef UINT8 EFI_FV_FILETYPE;

typedef void * EFI_PEI_FILE_HANDLE;

typedef EFI_STATUS (* EFI_PEI_FFS_FIND_NEXT_FILE2)(EFI_PEI_SERVICES * *, EFI_FV_FILETYPE, EFI_PEI_FV_HANDLE, EFI_PEI_FILE_HANDLE *);

typedef UINT8 EFI_SECTION_TYPE;

typedef EFI_STATUS (* EFI_PEI_FFS_FIND_SECTION_DATA2)(EFI_PEI_SERVICES * *, EFI_SECTION_TYPE, EFI_PEI_FILE_HANDLE, void * *);

typedef UINT64 EFI_PHYSICAL_ADDRESS;

typedef EFI_STATUS (* EFI_PEI_INSTALL_PEI_MEMORY)(EFI_PEI_SERVICES * *, EFI_PHYSICAL_ADDRESS, UINT64);

enum enum_16 {
    EfiBootServicesCode=3,
    EfiRuntimeServicesData=6,
    EfiMemoryMappedIOPortSpace=12,
    EfiLoaderData=2,
    EfiBootServicesData=4,
    EfiLoaderCode=1,
    EfiReservedMemoryType=0,
    EfiRuntimeServicesCode=5,
    EfiACPIReclaimMemory=9,
    EfiMaxMemoryType=15,
    EfiConventionalMemory=7,
    EfiMemoryMappedIO=11,
    EfiPalCode=13,
    EfiPersistentMemory=14,
    EfiACPIMemoryNVS=10,
    EfiUnusableMemory=8
};

typedef enum enum_16 EFI_MEMORY_TYPE;

typedef EFI_STATUS (* EFI_PEI_ALLOCATE_PAGES)(EFI_PEI_SERVICES * *, EFI_MEMORY_TYPE, UINTN, EFI_PHYSICAL_ADDRESS *);

typedef EFI_STATUS (* EFI_PEI_ALLOCATE_POOL)(EFI_PEI_SERVICES * *, UINTN, void * *);

typedef void (* EFI_PEI_COPY_MEM)(void *, void *, UINTN);

typedef void (* EFI_PEI_SET_MEM)(void *, UINTN, UINT8);

typedef UINT32 EFI_STATUS_CODE_TYPE;

typedef UINT32 EFI_STATUS_CODE_VALUE;

typedef EFI_STATUS (* EFI_PEI_REPORT_STATUS_CODE)(EFI_PEI_SERVICES * *, EFI_STATUS_CODE_TYPE, EFI_STATUS_CODE_VALUE, UINT32, EFI_GUID *, struct EFI_STATUS_CODE_DATA *);

typedef EFI_STATUS (* EFI_PEI_RESET_SYSTEM)(EFI_PEI_SERVICES * *);


typedef EFI_STATUS (* EFI_PEI_FFS_FIND_BY_NAME)(EFI_GUID *, EFI_PEI_FV_HANDLE, EFI_PEI_FILE_HANDLE *);

typedef EFI_STATUS (* EFI_PEI_FFS_GET_FILE_INFO)(EFI_PEI_FILE_HANDLE, struct EFI_FV_FILE_INFO *);

typedef EFI_STATUS (* EFI_PEI_FFS_GET_VOLUME_INFO)(EFI_PEI_FV_HANDLE, struct EFI_FV_INFO *);

typedef EFI_STATUS (* EFI_PEI_REGISTER_FOR_SHADOW)(EFI_PEI_FILE_HANDLE);

typedef EFI_STATUS (* EFI_PEI_FFS_FIND_SECTION_DATA3)(EFI_PEI_SERVICES * *, EFI_SECTION_TYPE, UINTN, EFI_PEI_FILE_HANDLE, void * *, UINT32 *);

typedef EFI_STATUS (* EFI_PEI_FFS_GET_FILE_INFO2)(EFI_PEI_FILE_HANDLE, struct EFI_FV_FILE_INFO2 *);

enum enum_17 {
    EfiResetCold=0,
    EfiResetShutdown=2,
    EfiResetWarm=1,
    EfiResetPlatformSpecific=3
};

typedef enum enum_17 EFI_RESET_TYPE;

typedef void (* EFI_PEI_RESET2_SYSTEM)(EFI_RESET_TYPE, EFI_STATUS, UINTN, void *);

typedef EFI_STATUS (* EFI_PEI_FREE_PAGES)(EFI_PEI_SERVICES * *, EFI_PHYSICAL_ADDRESS, UINTN);

typedef EFI_STATUS (* EFI_PEIM_NOTIFY_ENTRY_POINT)(EFI_PEI_SERVICES * *, EFI_PEI_NOTIFY_DESCRIPTOR *, void *);

typedef UINT8 (* EFI_PEI_CPU_IO_PPI_IO_READ8)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef UINT16 (* EFI_PEI_CPU_IO_PPI_IO_READ16)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef UINT32 (* EFI_PEI_CPU_IO_PPI_IO_READ32)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef UINT64 (* EFI_PEI_CPU_IO_PPI_IO_READ64)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef void (* EFI_PEI_CPU_IO_PPI_IO_WRITE8)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT8);

typedef void (* EFI_PEI_CPU_IO_PPI_IO_WRITE16)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT16);

typedef void (* EFI_PEI_CPU_IO_PPI_IO_WRITE32)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT32);

typedef void (* EFI_PEI_CPU_IO_PPI_IO_WRITE64)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT64);

typedef UINT8 (* EFI_PEI_CPU_IO_PPI_MEM_READ8)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef UINT16 (* EFI_PEI_CPU_IO_PPI_MEM_READ16)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef UINT32 (* EFI_PEI_CPU_IO_PPI_MEM_READ32)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef UINT64 (* EFI_PEI_CPU_IO_PPI_MEM_READ64)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64);

typedef void (* EFI_PEI_CPU_IO_PPI_MEM_WRITE8)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT8);

typedef void (* EFI_PEI_CPU_IO_PPI_MEM_WRITE16)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT16);

typedef void (* EFI_PEI_CPU_IO_PPI_MEM_WRITE32)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT32);

typedef void (* EFI_PEI_CPU_IO_PPI_MEM_WRITE64)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, UINT64, UINT64);

enum enum_897 {
    EfiPeiPciCfgWidthUint64=3,
    EfiPeiPciCfgWidthUint32=2,
    EfiPeiPciCfgWidthUint8=0,
    EfiPeiPciCfgWidthUint16=1,
    EfiPeiPciCfgWidthMaximum=4
};

typedef enum enum_897 EFI_PEI_PCI_CFG_PPI_WIDTH;

typedef EFI_STATUS (* EFI_PEI_PCI_CFG2_PPI_IO)(EFI_PEI_SERVICES * *, EFI_PEI_PCI_CFG2_PPI *, EFI_PEI_PCI_CFG_PPI_WIDTH, UINT64, void *);

typedef EFI_STATUS (* EFI_PEI_PCI_CFG2_PPI_RW)(EFI_PEI_SERVICES * *, EFI_PEI_PCI_CFG2_PPI *, EFI_PEI_PCI_CFG_PPI_WIDTH, UINT64, void *, void *);

typedef UINT32 EFI_FV_FILE_ATTRIBUTES;

typedef UINT32 EFI_FVB_ATTRIBUTES_2;

enum enum_868 {
    EfiPeiCpuIoWidthFifoUint16=5,
    EfiPeiCpuIoWidthFillUint32=10,
    EfiPeiCpuIoWidthFillUint16=9,
    EfiPeiCpuIoWidthFifoUint64=7,
    EfiPeiCpuIoWidthFifoUint32=6,
    EfiPeiCpuIoWidthFillUint8=8,
    EfiPeiCpuIoWidthUint8=0,
    EfiPeiCpuIoWidthUint16=1,
    EfiPeiCpuIoWidthMaximum=12,
    EfiPeiCpuIoWidthUint64=3,
    EfiPeiCpuIoWidthUint32=2,
    EfiPeiCpuIoWidthFifoUint8=4,
    EfiPeiCpuIoWidthFillUint64=11
};

typedef enum enum_868 EFI_PEI_CPU_IO_PPI_WIDTH;

typedef EFI_STATUS (* EFI_PEI_CPU_IO_PPI_IO_MEM)(EFI_PEI_SERVICES * *, EFI_PEI_CPU_IO_PPI *, EFI_PEI_CPU_IO_PPI_WIDTH, UINT64, UINTN, void *);

struct _EFI_PEI_NOTIFY_DESCRIPTOR {
    UINTN Flags;
    EFI_GUID * Guid;
    EFI_PEIM_NOTIFY_ENTRY_POINT Notify;
};

struct EFI_FV_FILE_INFO2 __packed {
    EFI_GUID FileName;
    EFI_FV_FILETYPE FileType;
    EFI_FV_FILE_ATTRIBUTES FileAttributes;
    void * Buffer;
    UINT32 BufferSize;
    UINT32 AuthenticationStatus;
};

struct EFI_TABLE_HEADER __packed {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
};

struct EFI_PEI_CPU_IO_PPI_ACCESS {
    EFI_PEI_CPU_IO_PPI_IO_MEM Read;
    EFI_PEI_CPU_IO_PPI_IO_MEM Write;
};

struct EFI_PEI_CPU_IO_PPI {
    struct EFI_PEI_CPU_IO_PPI_ACCESS Mem;
    struct EFI_PEI_CPU_IO_PPI_ACCESS Io;
    EFI_PEI_CPU_IO_PPI_IO_READ8 IoRead8;
    EFI_PEI_CPU_IO_PPI_IO_READ16 IoRead16;
    EFI_PEI_CPU_IO_PPI_IO_READ32 IoRead32;
    EFI_PEI_CPU_IO_PPI_IO_READ64 IoRead64;
    EFI_PEI_CPU_IO_PPI_IO_WRITE8 IoWrite8;
    EFI_PEI_CPU_IO_PPI_IO_WRITE16 IoWrite16;
    EFI_PEI_CPU_IO_PPI_IO_WRITE32 IoWrite32;
    EFI_PEI_CPU_IO_PPI_IO_WRITE64 IoWrite64;
    EFI_PEI_CPU_IO_PPI_MEM_READ8 MemRead8;
    EFI_PEI_CPU_IO_PPI_MEM_READ16 MemRead16;
    EFI_PEI_CPU_IO_PPI_MEM_READ32 MemRead32;
    EFI_PEI_CPU_IO_PPI_MEM_READ64 MemRead64;
    EFI_PEI_CPU_IO_PPI_MEM_WRITE8 MemWrite8;
    EFI_PEI_CPU_IO_PPI_MEM_WRITE16 MemWrite16;
    EFI_PEI_CPU_IO_PPI_MEM_WRITE32 MemWrite32;
    EFI_PEI_CPU_IO_PPI_MEM_WRITE64 MemWrite64;
};

struct EFI_FV_INFO {
    EFI_FVB_ATTRIBUTES_2 FvAttributes;
    EFI_GUID FvFormat;
    EFI_GUID FvName;
    void * FvStart;
    UINT64 FvSize;
};

struct EFI_PEI_PCI_CFG2_PPI {
    EFI_PEI_PCI_CFG2_PPI_IO Read;
    EFI_PEI_PCI_CFG2_PPI_IO Write;
    EFI_PEI_PCI_CFG2_PPI_RW Modify;
    UINT16 Segment;
};

struct EFI_PEI_PPI_DESCRIPTOR {
    UINTN Flags;
    EFI_GUID * Guid;
    void * Ppi;
};

struct EFI_FV_FILE_INFO {
    EFI_GUID FileName;
    EFI_FV_FILETYPE FileType;
    EFI_FV_FILE_ATTRIBUTES FileAttributes;
    void * Buffer;
    UINT32 BufferSize;
};

struct _EFI_PEI_SERVICES {
    struct EFI_TABLE_HEADER Hdr;
    EFI_PEI_INSTALL_PPI InstallPpi;
    EFI_PEI_REINSTALL_PPI ReInstallPpi;
    EFI_PEI_LOCATE_PPI LocatePpi;
    EFI_PEI_NOTIFY_PPI NotifyPpi;
    EFI_PEI_GET_BOOT_MODE GetBootMode;
    EFI_PEI_SET_BOOT_MODE SetBootMode;
    EFI_PEI_GET_HOB_LIST GetHobList;
    EFI_PEI_CREATE_HOB CreateHob;
    EFI_PEI_FFS_FIND_NEXT_VOLUME2 FfsFindNextVolume;
    EFI_PEI_FFS_FIND_NEXT_FILE2 FfsFindNextFile;
    EFI_PEI_FFS_FIND_SECTION_DATA2 FfsFindSectionData;
    EFI_PEI_INSTALL_PEI_MEMORY InstallPeiMemory;
    EFI_PEI_ALLOCATE_PAGES AllocatePages;
    EFI_PEI_ALLOCATE_POOL AllocatePool;
    EFI_PEI_COPY_MEM CopyMem;
    EFI_PEI_SET_MEM SetMem;
    EFI_PEI_REPORT_STATUS_CODE ReportStatusCode;
    EFI_PEI_RESET_SYSTEM ResetSystem;
    EFI_PEI_CPU_IO_PPI * CpuIo;
    EFI_PEI_PCI_CFG2_PPI * PciCfg;
    EFI_PEI_FFS_FIND_BY_NAME FfsFindFileByName;
    EFI_PEI_FFS_GET_FILE_INFO FfsGetFileInfo;
    EFI_PEI_FFS_GET_VOLUME_INFO FfsGetVolumeInfo;
    EFI_PEI_REGISTER_FOR_SHADOW RegisterForShadow;
    EFI_PEI_FFS_FIND_SECTION_DATA3 FindSectionData3;
    EFI_PEI_FFS_GET_FILE_INFO2 FfsGetFileInfo2;
    EFI_PEI_RESET2_SYSTEM ResetSystem2;
    EFI_PEI_FREE_PAGES FreePages;
};

struct EFI_STATUS_CODE_DATA {
    UINT16 HeaderSize;
    UINT16 Size;
    EFI_GUID Type;
};

