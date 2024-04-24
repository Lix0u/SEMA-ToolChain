import logging
import angr
import sys

sys.set_int_max_str_digits(0)
lw = logging.getLogger("CustomSimProcedureWindows")


class WriteProcessMemory(angr.SimProcedure):

    def run(
        self,
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesWritten
    ):
        x = self.state.solver.eval(nSize)
        y = self.state.memory.load(lpBuffer,x)
        print(y)
        print(x)
        print(lpBaseAddress)
        
        self.state.memory.store(lpBaseAddress, y, size=x)
        return 0x1
