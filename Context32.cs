using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpBlock {
    public class Context32 : Context {

        WinAPI.CONTEXT ctx = new WinAPI.CONTEXT();

        public override ulong Ip { 
            get => ctx.Eip ; set => ctx.Eip = (uint)value; 
        }

        protected override object ContextStruct { get => ctx; set => ctx = (WinAPI.CONTEXT)value; }

        public Context32(ContextFlags contextFlags) {
            switch (contextFlags) {
                case ContextFlags.All:
                    ctx.ContextFlags = WinAPI.CONTEXT_FLAGS.CONTEXT_ALL;
                    break;
                case ContextFlags.Debug:
                    ctx.ContextFlags = WinAPI.CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS;
                    break;
            }
        }

        public override ulong GetCurrentReturnAddress(IntPtr hProcess) {
            byte[] returnAddress = new byte[4];
            IntPtr bytesRead;
            WinAPI.ReadProcessMemory(hProcess, new IntPtr((long)ctx.Esp), returnAddress, 4, out bytesRead);
            return BitConverter.ToUInt32(returnAddress, 0);
        }

        public override void SetResultRegister(ulong result) {
            ctx.Eax = (uint)result;
        }

        public override void PopStackPointer() {
            ctx.Esp += 4;
        }

        public override void EnableBreakpoint(IntPtr address, int index) {
            //Currently only supports first hardware breakpoint, could
            //be expanded to support up to 4 hardware breakpoint for altering
            //ETW and other potensial bypasses
            ctx.Dr0 = (uint)address.ToInt32();
            //Set bits 16-19 as 0, DR0 for execute HBP
            ctx.Dr7 = (uint)SetBits((ulong)ctx.Dr7, 16, 4, 0);
            //Set DR0 HBP as enabled
            ctx.Dr7 = (uint)SetBits((ulong)ctx.Dr7, 0, 2, 3);
            ctx.Dr6 = 0;
        }

        public override void EnableSingleStep() {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags |= (1 << 8);
        }

        public override void ClearBreakpoint(int index) {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags = 0;
        }

        protected override bool SetContext(IntPtr thread, IntPtr context) {
            return WinAPI.SetThreadContext(thread, context);
        }

        protected override bool GetContext(IntPtr thread, IntPtr context) {
            return WinAPI.GetThreadContext(thread, context);
        }

        public override void SetRegister(int index, long value) {
            switch (index) {
                case 0:
                    ctx.Eax = (uint)value;
                    break;
                case 1:
                    ctx.Ebx = (uint)value;
                    break;
                case 2:
                    ctx.Ecx = (uint)value;
                    break;
                case 3:
                    ctx.Edx = (uint)value;
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        public override long GetRegister(int index) {
            switch (index) {
                case 0:
                    return (long)ctx.Eax;
                case 1:
                    return (long)ctx.Ebx;
                case 2:
                    return (long)ctx.Ecx;
                case 3:
                    return (long)ctx.Edx;
                default:
                    throw new NotImplementedException();
            }
        }

        public override long GetParameter(int index, IntPtr hProcess) {
            long parameterAddress = ctx.Esp + 4 + (index * 4);            
            byte[] parameterValue = new byte[4];
            IntPtr bytesRead;
            WinAPI.ReadProcessMemory(hProcess, new IntPtr(parameterAddress), parameterValue, 4, out bytesRead);
            return BitConverter.ToUInt32(parameterValue, 0);
        }
    }
}
