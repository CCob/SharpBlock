using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpBlock {

    public enum ContextFlags {
        All,
        Debug
    }

    public abstract class Context : IDisposable  {
       
        IntPtr mem;
        IntPtr memAligned;

        public Context() {
            //Get/SetThreadContext needs to be 16 byte aligned memory offset on x64
            mem = Marshal.AllocHGlobal(Marshal.SizeOf(ContextStruct) + 15);
            memAligned = new IntPtr(mem.ToInt64() & ~0xF);
        }

        public void Dispose() {
            if(mem != IntPtr.Zero) {
                Marshal.FreeHGlobal(mem);
            }
        }

        public bool GetContext(IntPtr thread) {
            Marshal.StructureToPtr(ContextStruct, memAligned, false);
            bool result = GetContext(thread, memAligned);
            ContextStruct = Marshal.PtrToStructure(memAligned, ContextStruct.GetType());
            return result;
        }

        public bool SetContext(IntPtr thread){
            Marshal.StructureToPtr(ContextStruct, memAligned, false);
            return SetContext(thread, memAligned);
        }

        public ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue) {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }

        protected abstract object ContextStruct { get; set; }

        protected abstract bool SetContext(IntPtr thread, IntPtr context);

        protected abstract bool GetContext(IntPtr thread, IntPtr context);

        public abstract ulong Ip { get; set; }

        public abstract void SetResultRegister(ulong result);

        public abstract ulong GetCurrentReturnAddress(IntPtr hProcess);

        public abstract void PopStackPointer();

        public abstract void EnableBreakpoint(IntPtr address, int index);

        public abstract void ClearBreakpoint(int index);

        public abstract void EnableSingleStep();
    }
}
