import angr


class sigprocmask(angr.SimProcedure):
    def run(self, how, set_, oldset):
        # self.state.memory.store(oldset, self.state.posix.sigmask(sigsetsize=sigsetsize), condition=oldset != 0)
        # self.state.posix.sigprocmask(how, self.state.memory.load(set_, sigsetsize), sigsetsize, valid_ptr=set_!=0)
        return 0
        # TODO: EFAULT
        # return self.state.solver.If(self.state.solver.And(how != self.state.posix.SIG_BLOCK,how != self.state.posix.SIG_UNBLOCK,how != self.state.posix.SIG_SETMASK),self.state.solver.BVV(self.state.posix.EINVAL, self.state.arch.bits),self.state.solver.BVV(0, self.state.arch.bits),)