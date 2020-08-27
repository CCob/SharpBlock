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

        public override void EnableBreakpoint(IntPtr address, int index) {

            switch (index) {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }
           
            //Set bits 16-31 as 0, which sets
            //DR0-DR3 HBP's for execute HBP
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            
            //Set DRx HBP as enabled for local mode
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;
        }

        public override void EnableSingleStep() {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags |= (1 << 8);
        }

        public override void ClearBreakpoint(int index) {

            //Clear the releveant hardware breakpoint
            switch (index) {
                case 0:
                    ctx.Dr0 = 0;
                    break;
                case 1:
                    ctx.Dr1 = 0;
                    break;
                case 2:
                    ctx.Dr2 = 0;
                    break;
                case 3:
                    ctx.Dr3 = 0;
                    break;
            }

            //Clear DRx HBP to disable for local mode
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 0);
            ctx.Dr6 = 0;
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
