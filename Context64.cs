using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpBlock {
    public class Context64 : Context {

        WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64();

        public override ulong Ip {
            get => ctx.Rip; set => ctx.Rip = value;
        }
        protected override object ContextStruct { get => ctx; set => ctx = (WinAPI.CONTEXT64)value; }

        public Context64(ContextFlags contextFlags) {
            switch (contextFlags) {
                case ContextFlags.All:
                    ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;
                    break;
                case ContextFlags.Debug:
                    ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_DEBUG_REGISTERS;
                    break;
            }
        }

        public override ulong GetCurrentReturnAddress(IntPtr hProcess) {
            byte[] returnAddress = new byte[8];
            IntPtr bytesRead;
            WinAPI.ReadProcessMemory(hProcess, new IntPtr((long)ctx.Rsp), returnAddress,8, out bytesRead);
            return BitConverter.ToUInt64(returnAddress, 0);
        }

        public override void SetResultRegister(ulong result) {
            ctx.Rax = result;
        }

        public void SetRegister(int index, long value) {
            switch (index) {
                case 0:
                    ctx.Rax = (ulong)value;
                    break;
                case 1:
                    ctx.Rbx = (ulong)value;
                    break;
                case 2:
                    ctx.Rcx = (ulong)value;
                    break;
                case 3:
                    ctx.Rdx = (ulong)value;
                    break;
                default:
                    throw new NotImplementedException();
            }           
        }

        public long GetRegister(int index) {
            switch (index) {
                case 0:
                    return (long)ctx.Rax;
                case 1:
                    return (long)ctx.Rbx;
                case 2:
                    return (long)ctx.Rcx;
                case 3:
                    return (long)ctx.Rdx;
                default:
                    throw new NotImplementedException();
            }
        }

        public override void PopStackPointer() {
            ctx.Rsp += 8;
        }

        public override void EnableBreakpoint(IntPtr address) {
            //Currently only supports first hardware breakpoint, could
            //be expanded to support up to 4 hardware breakpoint for altering
            //ETW and other potensial bypasses
            ctx.Dr0 = (ulong)address.ToInt64();
            //Set bits 16-19 as 0, DR0 for execute HBP
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 4, 0);
            //Set DR0 HBP as enabled
            ctx.Dr7 = SetBits(ctx.Dr7, 0, 2, 3);
            ctx.Dr6 = 0;
        }

        public override void EnableSingleStep() {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags |= (1 << 8);
        }

        public override void ClearBreakpoint() {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags = 0;
        }

        protected override bool SetContext(IntPtr thread, IntPtr context) {
            return WinAPI.SetThreadContext(thread, context);
        }

        protected override bool GetContext(IntPtr thread, IntPtr context) {
            return WinAPI.GetThreadContext(thread, context);
        }
    }
}
