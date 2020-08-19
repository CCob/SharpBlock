using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpBlock {
    class PE {


        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct LIST_ENTRY {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct LDR_DATA_TABLE_ENTRY {
            public LIST_ENTRY InLoadOrderModuleListPtr;
            public LIST_ENTRY InMemoryOrderModuleListPtr;
            public LIST_ENTRY InInitOrderModuleListPtr;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
        }

       
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct PEB_LDR_DATA {
            public int Length;
            public int Initialized;
            public int SsHandle;
            public LIST_ENTRY InLoadOrderModuleListPtr;
            public LIST_ENTRY InMemoryOrderModuleListPtr;
            public LIST_ENTRY InInitOrderModuleListPtr;
            public int EntryInProgress;
            public int ShutdownInProgress;
            public int ShutdownThreadId;         
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s) {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose() {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString() {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CURDIR {
            public UNICODE_STRING DosPath;
            public IntPtr Handle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS {
            public uint MaxLen;
            public uint Len;
            public uint Flags;
            public uint DebugFlags;
            public IntPtr ConsoleHandle;
            public uint ConsoleFlags;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;
            public CURDIR CurrentDirectory;
            public UNICODE_STRING DllPath;
            public UNICODE_STRING ImagePathName;
            public UNICODE_STRING CommandLine;
            public IntPtr Environment;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LOAD_CONFIGURATION_LAYOUT_64 {
            public int Characteristics;
            public int TimeDataStamp;
            public short MajorVersion;
            public short MinorVersion;
            public int GlobalFlagsClear;
            public int GlobalFlagsSet;
            public int CriticalScetionDefaultTimeout;
            public long DeCommitFreeBlockThreshhold;
            public long DeCommitTotalFreeThreshhold;
            public long LockPrefixTable;
            public long MaximumAllocationSize;
            public long VirtualMemoryThreshhold;
            public long ProcessAfinityMask;
            public int ProcessHeapFlags;
            public short CSDVersion;
            public short Reserved;
            public long EditList;
            public long SecurityCookie;
            public long SEHandlerTable;
            public long SEHandlerCount;
            public long GuardCFCheckFunctionPointer;
            public long GuardCFDispatchFunctionPointer;
            public long GuardCFFunctionPointer;
            public long GuardCFFunctionCount;
            public int GuardFlags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] CodeIntegrity;
            public long GuardAddressTakenIatEntryTable;
            public long GuardAddressTakenIatEntryCount;
            public long GuardLongJumpTargetTable;
            public long GuardLongJumpTargetCount;
        }
            
        public struct IMAGE_DOS_HEADER {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        public enum MagicType : ushort {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum DllCharacteristicsType : ushort {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        public enum SubSystemType : ushort {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32 {
            [FieldOffset(0)]
            public MagicType Magic;
            [FieldOffset(2)]
            public byte MajorLinkerVersion;
            [FieldOffset(3)]
            public byte MinorLinkerVersion;
            [FieldOffset(4)]
            public uint SizeOfCode;
            [FieldOffset(8)]
            public uint SizeOfInitializedData;
            [FieldOffset(12)]
            public uint SizeOfUninitializedData;
            [FieldOffset(16)]
            public uint AddressOfEntryPoint;
            [FieldOffset(20)]
            public uint BaseOfCode;
            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;
            [FieldOffset(28)]
            public uint ImageBase;
            [FieldOffset(32)]
            public uint SectionAlignment;
            [FieldOffset(36)]
            public uint FileAlignment;
            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;
            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;
            [FieldOffset(44)]
            public ushort MajorImageVersion;
            [FieldOffset(46)]
            public ushort MinorImageVersion;
            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;
            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;
            [FieldOffset(52)]
            public uint Win32VersionValue;
            [FieldOffset(56)]
            public uint SizeOfImage;
            [FieldOffset(60)]
            public uint SizeOfHeaders;
            [FieldOffset(64)]
            public uint CheckSum;
            [FieldOffset(68)]
            public SubSystemType Subsystem;
            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;
            [FieldOffset(72)]
            public uint SizeOfStackReserve;
            [FieldOffset(76)]
            public uint SizeOfStackCommit;
            [FieldOffset(80)]
            public uint SizeOfHeapReserve;
            [FieldOffset(84)]
            public uint SizeOfHeapCommit;
            [FieldOffset(88)]
            public uint LoaderFlags;
            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;
            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;
            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;
            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;
            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;
            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;
            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;
            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;
            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;
            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;
            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64 {
            [FieldOffset(0)]
            public MagicType Magic;
            [FieldOffset(2)]
            public byte MajorLinkerVersion;
            [FieldOffset(3)]
            public byte MinorLinkerVersion;
            [FieldOffset(4)]
            public uint SizeOfCode;
            [FieldOffset(8)]
            public uint SizeOfInitializedData;
            [FieldOffset(12)]
            public uint SizeOfUninitializedData;
            [FieldOffset(16)]
            public uint AddressOfEntryPoint;
            [FieldOffset(20)]
            public uint BaseOfCode;
            [FieldOffset(24)]
            public ulong ImageBase;
            [FieldOffset(32)]
            public uint SectionAlignment;
            [FieldOffset(36)]
            public uint FileAlignment;
            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;
            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;
            [FieldOffset(44)]
            public ushort MajorImageVersion;
            [FieldOffset(46)]
            public ushort MinorImageVersion;
            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;
            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;
            [FieldOffset(52)]
            public uint Win32VersionValue;
            [FieldOffset(56)]
            public uint SizeOfImage;
            [FieldOffset(60)]
            public uint SizeOfHeaders;
            [FieldOffset(64)]
            public uint CheckSum;
            [FieldOffset(68)]
            public SubSystemType Subsystem;
            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;
            [FieldOffset(72)]
            public ulong SizeOfStackReserve;
            [FieldOffset(80)]
            public ulong SizeOfStackCommit;
            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;
            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;
            [FieldOffset(104)]
            public uint LoaderFlags;
            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;
            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;
            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;
            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;
            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;
            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;
            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;
            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;
            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;
            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;
            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER {
            public UInt32 Signature;
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }
    }
}
