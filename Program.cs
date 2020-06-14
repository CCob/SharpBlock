using Mono.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static SharpBlock.WinAPI;

namespace SharpBlock {

    class Program {

        static List<string> blockDllName = new List<string>();
        static List<string> blockDescription = new List<string>();
        static List<string> blockCopyright = new List<string>();
        static List<string> blockProduct = new List<string>();
 
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
            PE.IMAGE_FILE_HEADER fileHeader = (PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure( new IntPtr(mem.ToInt64() + dosHeader.e_lfanew) , typeof(PE.IMAGE_FILE_HEADER));

            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            IntPtr entryPoint;
            if ( (fileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE) {
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

        static void Main(string[] args) {

            string program = "c:\\windows\\system32\\cmd.exe";
            string programArgs = "";
            bool showHelp = false;

            Console.WriteLine(
                "SharpBlock by @_EthicalChaos_\n" +
                 "  DLL Blocking app for child processes\n"
                );

            OptionSet option_set = new OptionSet()
                .Add("e=|exe=", "Program to execute (default cmd.exe)", v => program = v)
                .Add("a=|args=", "Arguments for program (default null)", v => programArgs = v)
                .Add("n=|name=", "Name of DLL to block", v => blockDllName.Add(v) )
                .Add("c=|copyright=", "Copyright string to block", v => blockCopyright.Add(v))
                .Add("p=|product=", "Product string to block", v => blockProduct.Add(v))
                .Add("d=|description=", "Description string to block", v => blockDescription.Add(v))
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

            STARTUPINFO startupInfo =  new STARTUPINFO();
            startupInfo.cb = (uint)Marshal.SizeOf(startupInfo);
            PROCESS_INFORMATION pi =  new PROCESS_INFORMATION();

            if(!CreateProcess(program, $"\"{program}\" {programArgs}", IntPtr.Zero, IntPtr.Zero, true, WinAPI.DEBUG_PROCESS, IntPtr.Zero, null,
                ref startupInfo, out pi)) {
                Console.WriteLine($"[!] Failed to create process {program}");
                return;
            }
          
            Console.WriteLine($"[+] Launched process {program} with PID {pi.dwProcessId}");

            bool bContinueDebugging = true;
            Dictionary<uint, IntPtr> processHandles = new Dictionary<uint, IntPtr>();
  
            while (bContinueDebugging) {
                IntPtr debugEventPtr = Marshal.AllocHGlobal(1024);
                bool bb = WinAPI.WaitForDebugEvent(debugEventPtr, 1000);
                UInt32 dwContinueDebugEvent = WinAPI.DBG_CONTINUE;
                if (bb) {
                    WinAPI.DEBUG_EVENT DebugEvent = (WinAPI.DEBUG_EVENT)Marshal.PtrToStructure(debugEventPtr, typeof(WinAPI.DEBUG_EVENT));
                    IntPtr debugInfoPtr = GetIntPtrFromByteArray(DebugEvent.u);
                    switch (DebugEvent.dwDebugEventCode) {
                        case WinAPI.CREATE_PROCESS_DEBUG_EVENT:
                            WinAPI.CREATE_PROCESS_DEBUG_INFO CreateProcessDebugInfo = (WinAPI.CREATE_PROCESS_DEBUG_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.CREATE_PROCESS_DEBUG_INFO));
                            processHandles.Add(DebugEvent.dwProcessId, CreateProcessDebugInfo.hProcess);
                            break;
                        case WinAPI.EXIT_PROCESS_DEBUG_EVENT:
                            if(pi.dwProcessId == DebugEvent.dwProcessId)
                                bContinueDebugging = false;
                            break;
                        case WinAPI.LOAD_DLL_DEBUG_EVENT:
                            WinAPI.LOAD_DLL_DEBUG_INFO LoadDLLDebugInfo = (WinAPI.LOAD_DLL_DEBUG_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.LOAD_DLL_DEBUG_INFO));
                            PatchEntryPointIfNeeded(LoadDLLDebugInfo.hFile, LoadDLLDebugInfo.lpBaseOfDll, processHandles[DebugEvent.dwProcessId]);
                            break;
                    }
 
                    WinAPI.ContinueDebugEvent((uint)DebugEvent.dwProcessId,                               
                        (uint)DebugEvent.dwThreadId,
                        dwContinueDebugEvent);
                }
                if (debugEventPtr != null)
                    Marshal.FreeHGlobal(debugEventPtr);
            }
        }
    }
}
