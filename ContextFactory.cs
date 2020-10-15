using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpBlock {
    public static class ContextFactory {         
        public static Context Create(ContextFlags contextFlags) {
            if(IntPtr.Size == 8) {
                return new Context64(contextFlags);
            } else {
                return new Context32(contextFlags);
            }
        }
    }
}
