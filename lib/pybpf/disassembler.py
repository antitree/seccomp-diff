import logging
from lib.pybpf.common import BPFConstants
import lib.syscalls.x86_64 as syscalls

# TODO expand support syscalls
SYSCALLS = syscalls.syscall_dict

class BPFInvalidOpcode(Exception):
    pass

class BPFDecoder(BPFConstants):
    def __init__(self):
        self.current = None
        self.last = None
        self.action = None

    def decode_one(self, op, jt, jf, k):
        class_ =  op & 0x07
        if class_ == self.BPF_LD:
            mode = op & 0xE0
            if mode == self.BPF_IMM:
                return self.op_set_a_imm(k)
            elif mode == self.BPF_MEM:
                return self.op_set_a_mem(k)
            else:
                size = op & 0x18
                if size == self.BPF_W:
                    size = 4
                elif size == self.BPF_H:
                    size = 2
                elif size == self.BPF_B:
                    size = 1
                else:
                    raise BPFInvalidOpcode(op)
                if mode == self.BPF_ABS:
                    return self.op_set_a_abs(k, size)
                elif mode == self.BPF_IND:
                    return self.op_set_a_ind(k, size)
                else:
                    raise BPFInvalidOpcode(op)
        elif class_ == self.BPF_LDX:
            mode = op & (0x18 | 0xE0)
            if mode == self.BPF_W | self.BPF_IMM:
                return self.op_set_x_imm(k)
            elif mode == self.BPF_W | self.BPF_MEM:
                return self.op_set_x_mem(k)
            elif mode == self.BPF_B | self.BPF_MSH:
                return self.op_set_x_msh(k)
            else:
                raise BPFInvalidOpcode(op)
        elif class_ == self.BPF_ST:
            return self.op_set_mem_a(k)
        elif class_ == self.BPF_STX:
            return self.op_set_mem_x(k)
        elif class_ == self.BPF_ALU:
            opr = op & (0xF0 | 0x08)
            if opr == self.BPF_ADD | self.BPF_K:
                return self.op_alu_add_k(k)
            elif opr == self.BPF_SUB | self.BPF_K:
                return self.op_alu_sub_k(k)
            elif opr == self.BPF_MUL | self.BPF_K:
                return self.op_alu_mul_k(k)
            elif opr == self.BPF_DIV | self.BPF_K:
                return self.op_alu_div_k(k)
            elif opr == self.BPF_OR | self.BPF_K:
                return self.op_alu_or_k(k)
            elif opr == self.BPF_AND | self.BPF_K:
                return self.op_alu_and_k(k)
            elif opr == self.BPF_LSH | self.BPF_K:
                return self.op_alu_lsh_k(k)
            elif opr == self.BPF_RSH | self.BPF_K:
                return self.op_alu_rsh_k(k)
            elif opr == self.BPF_NEG | self.BPF_K:
                return self.op_alu_neg()
            elif opr == self.BPF_MOD | self.BPF_K:
                return self.op_alu_mod_k(k)
            elif opr == self.BPF_XOR | self.BPF_K:
                return self.op_alu_xor_k(k)
            elif opr == self.BPF_ADD | self.BPF_X:
                return self.op_alu_add_x()
            elif opr == self.BPF_SUB | self.BPF_X:
                return self.op_alu_sub_x()
            elif opr == self.BPF_MUL | self.BPF_X:
                return self.op_alu_mul_x()
            elif opr == self.BPF_DIV | self.BPF_X:
                return self.op_alu_div_x()
            elif opr == self.BPF_OR | self.BPF_X:
                return self.op_alu_or_x()
            elif opr == self.BPF_AND | self.BPF_X:
                return self.op_alu_and_x()
            elif opr == self.BPF_LSH | self.BPF_X:
                return self.op_alu_lsh_x()
            elif opr == self.BPF_RSH | self.BPF_X:
                return self.op_alu_rsh_x()
            elif opr == self.BPF_NEG | self.BPF_X:
                return self.op_alu_neg()
            elif opr == self.BPF_MOD | self.BPF_X:
                return self.op_alu_mod_x()
            elif opr == self.BPF_XOR | self.BPF_X:
                return self.op_alu_xor_x()
        elif class_ == self.BPF_JMP:
            opr = op & (0xF0 | 0x08)
            if opr == self.BPF_JA:
                return self.op_jmp_a(k)
            elif opr == self.BPF_JGT | self.BPF_K:
                return self.op_jmp_gt_k(jt, jf, k)
            elif opr == self.BPF_JGE | self.BPF_K:
                return self.op_jmp_ge_k(jt, jf, k)
            elif opr == self.BPF_JEQ | self.BPF_K:
                return self.op_jmp_eq_k(jt, jf, k)
            elif opr == self.BPF_JSET | self.BPF_K:
                return self.op_jmp_set_k(jt, jf, k)
            elif opr == self.BPF_JGT | self.BPF_X:
                return self.op_jmp_gt_x(jt, jf)
            elif opr == self.BPF_JGE | self.BPF_X:
                return self.op_jmp_ge_x(jt, jf)
            elif opr == self.BPF_JEQ | self.BPF_X:
                return self.op_jmp_eq_x(jt, jf)
            elif opr == self.BPF_JSET | self.BPF_X:
                return self.op_jmp_set_x(jt, jf)
            else:
                raise BPFInvalidOpcode(op)
        elif class_ == self.BPF_RET:
            src = op & 0x18
            if src == self.BPF_K:
                return self.op_ret_k(k)
            elif src == self.BPF_X:
                return self.op_ret_x()
            elif src == self.BPF_A:
                return self.op_ret_a()
            else:
                raise BPFInvalidOpcode(op)
        elif class_ == self.BPF_MISC:
            misc = op & 0xF8
            if misc == self.BPF_TAX:
                return self.op_misc_tax()
            elif misc == self.BPF_TXA:
                return self.op_misc_txa()
            else:
                raise BPFInvalidOpcode(op)
        else:
            raise BPFInvalidOpcode(op)
        
    def op_set_a_abs(self, k, size):
        if size == 1:
            return "ldb [%d]" % k
        if size == 2:
            return "ldh [%d]" % k
        if size == 4:
            return "ld [%d]" % k


class BPFDisassembler(BPFDecoder):
    def __init__(self, prog=None):
        self.prog = prog
        self.cache = {}
        self.syscallSummary = dict()
        self.defaultAction = None
        
    @property
    def syscallSummary(self):
        return self._syscallSummary

    @syscallSummary.setter
    def syscallSummary(self, value):
        self._syscallSummary = value

    def __bool__(self):
        # Ensure `if obj.syscallSummary:` works intuitively
        return self._syscallSummary is not None
        
        
    def resolve_action(self, irec):
        
            
        if irec >= len(self.prog):
            logging.error(f"For some reason irec is incorrect: {irec} >= {len(self.prog)}")
        
        # Caching support. Likely unnecessary
        # if irec in self.cache:
        #     f_prog = self.cache[irec]
        # else:
        try: 
            f_prog = self.prog[irec]
        except Exception as e:
            logging.error(f"Fatal error trying to access bpf program: {e}")
            return None
            
        follow_s = self.disassemble_one(irec, f_prog)
        
        if "return" in follow_s.lower():
            follow_s = follow_s.split()[1]

            return follow_s
        else:
            logging.info(f"ERROR: the jump is not a return! {follow_s}")
            return "Unknown"
        
    def extract_default_action(self):
        """
        Extract the default action from the second-to-last instruction in the seccomp program.
        """
        
        if self.prog and len(self.prog) >= 2:
            # TODO: Make this more accurate
            # Get the second-to-last instruction
            # First attempt: It's the first return action in the filter
            # Wrong. There are lots of return actions scattered throughout.
            # Second attempt: It's the first return action of the end of the filter
            # Thid attempt: Just not sure...
            for idx in range(len(self.prog)-1,0, -1): 
            #second_to_last_instr = self.prog[-3]
                # Decode the action based on the instruction
                if (self.prog[idx].code & 0x07) == self.BPF_RET:
                    
                    action = self.prog[idx].k >> 16
                    if action == 0x0000:  # SECCOMP_RET_KILL_PROCESS
                        self.defaultAction = "KILL"
                    elif action == 0x7fff:  # SECCOMP_RET_ALLOW
                        self.defaultAction = "ALLOW"
                    elif action == 0x7ffc:  # SECCOMP_RET_LOG
                        self.defaultAction = "LOG"
                    elif action == 0x7ffe:  # SECCOMP_RET_TRACE
                        self.defaultAction = "TRACE"
                    elif action == 0x7ffd:  # SECCOMP_RET_TRAP
                        self.defaultAction = "TRAP"
                    elif action <= 0x0005:  # SECCOMP_RET_ERRNO
                        errno_value = self.prog[idx].k & 0x0000FFFF
                        self.defaultAction = f"ERRNO({errno_value})"
                    else:
                        self.defaultAction = "UNKNOWN"
                else:
                    break
        else:
            self.defaultAction = "N/A"
    
    def disassemble(self, prog):
        self.seccompDisassembled = []
        self.prog = prog
        
        self.extract_default_action()
        
        #mode = None
        for pc, instr in enumerate(self.prog):
            s = self.disassemble_one(pc, instr)            
            
            self.seccompDisassembled.append(f"l{pc:04}: {instr.code:02x} {instr.jt:02x} {instr.jf:02x} {instr.k:08x}\t{s}")
        return self.seccompDisassembled
        

    
    def disassemble_one(self, pc, instr):
        (op, jt, jl, k) = instr
        self.pc = pc
        return self.decode_one(op, jt, jl, k)

    def op_set_a_imm(self, k):
        return "ld #0x%x" % k

    def op_set_a_mem(self, k):
        return "ld M[%d]" % k

    def op_set_a_abs(self, k, size):
        
        if size == 1:
            return "ldb [%d]" % k
        if size == 2:
            return "ldh [%d]" % k
        if size == 4:
            if k == 4:      self.current = "ARCH"
            elif k == 0:    self.current = "SYSCALL"
            elif k == 16:   self.current = f"{self.last} ARGS[0]"
            else:           self.current = None
            return f"A = [{k}]({self.current})"

    def op_set_a_ind(self, k, size):
        if size == 1:
            return "ldb [x+%d]" % k
        if size == 2:
            return "ldh [x+%d]" % k
        if size == 4:
            return "ld [x+%d]" % k

    def op_set_x_imm(self, k):
        return "ldx #0x%x" % k

    def op_set_x_mem(self, k):
        return "ldx M[%d]" % k

    def op_set_x_msh(self, k):
        return "ldx 4*([%d] & 0xf)" % k

    def op_set_mem_a(self, k):
        return "st M[%d]" % k

    def op_set_mem_x(self, k):
        return "stx M[%d]" % k

    def op_alu_add_k(self, k):
        return "add #%d" % k
    def op_alu_sub_k(self, k):
        return "sub #%d" % k
    def op_alu_mul_k(self, k):
        return "mul #%d" % k
    def op_alu_div_k(self, k):
        return "div #%d" % k
    def op_alu_or_k(self, k):
        return "or #0x%x" % k
    def op_alu_and_k(self, k):
        return "and #0x%x" % k
    def op_alu_lsh_k(self, k):
        return "lsh #%d" % k
    def op_alu_rsh_k(self, k):
        return "rsh #%d" % k
    def op_alu_neg():
        return "neg"
    def op_alu_mod_k(self, k):
        return "mod #%d" % k
    def op_alu_xor_k(self, k):
        return "xor #0x%x" % k

    def op_alu_add_x(self):
        return "add x"
    def op_alu_sub_x(self):
        return "sub x"
    def op_alu_mul_x(self):
        return "mul x"
    def op_alu_div_x(self):
        return "div x"
    def op_alu_or_x(self):
        return "or x"
    def op_alu_and_x(self):
        return "and x"
    def op_alu_lsh_x(self):
        return "lsh x"
    def op_alu_rsh_x(self):
        return "rsh x"
    def op_alu_mod_x(self):
        return "mod x"
    def op_alu_xor_x(self):
        return "xor x"

    def op_ret_k(self, k):
        act = k >> 16
        if act == 5: #error
            n = k & 0xFF
            h = f"ERRORNO({n})"
            self.action = h
        elif act == 0x7fff:
            n = 0
            h = f"ALLOW"
            self.action = h
        elif act == 0:
            h = f"KILL"
            self.action = h
        elif act == 0x7ffc:
            h = f"LOG"
            self.action = h
        else:
            # TODO ther
            h = f"UNKNOWN"
            self.action = h
        return f"return {h}"
    def op_ret_x():
        return "ret x"
    def op_ret_a():
        return "ret a"

    def op_misc_tax(self):
        return "tax"
    def op_misc_txa(self):
        return "txa"

    def op_jmp_a(self, k):
        return "jmp l%d" % (self.pc+1+k)
    def op_jmp_gt_k(self, jt, jf, k):
        if jt == 0:
            return f"IF {self.current} <= {k}: {self.pc+1+jf}"
            #return "jle #0x%x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return f"IF {self.current} > {k}: {self.pc+1+jt}"
            return "jgt #0x%x, l%d" % (k, self.pc+1+jt)
        return "IF {self.current} > {k}: {self.pc+1+jt} else {self.pc+1+jf}"
        return "jgt #0x%x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_ge_k(self, jt, jf, k):
        if jt == 0:
            return "jlt #0x%x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jge #0x%x, l%d" % (k, self.pc+1+jt)
        return "jge #0x%x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)

    def op_jmp_eq_k(self, jt, jf, k):
        h = k
        action = ""
        pc = self.pc
        if jt == 0:
            # TODO consolidate with a helper function
            actionno = pc+1+jf
            if self.current == "SYSCALL":
                
                action = self.resolve_action(actionno)
                if k in SYSCALLS:
                    h = SYSCALLS[k][1]
                    if h in self.syscallSummary.keys():
                        self.syscallSummary[h]["count"] += 1
                        self.syscallSummary[h]["action"] = action
                    else: 
                        self.syscallSummary[h] = {"count": 1, "action": action}
                else:
                    h = f"UnknownSyscall{int(k)}/{hex(k)}"
                    if k in self.syscallSummary.keys():
                        self.syscallSummary[k]["count"] += 1
                    else: 
                        self.syscallSummary[k] = {"count": 1}
            self.last = h
            return f"IF {self.current} != {h}: {action}(l{actionno:04})"
        if jf == 0:
            if self.current == "SYSCALL": 
                actionno = pc+1+jt
                action = self.resolve_action(actionno)
                
                if k in SYSCALLS:
                    h = SYSCALLS[k][1]
                    if h in self.syscallSummary.keys():
                        self.syscallSummary[h]["count"] += 1
                        self.syscallSummary[h]["action"] = action
                    else: 
                        self.syscallSummary[h] = {"count": 1, "action": action}
                else:
                    h = f"UnknownSyscall{int(k)}/{hex(k)}"
                    if k in self.syscallSummary.keys():
                        self.syscallSummary[k]["count"] += 1
                        self.syscallSummary[k]["action"] = action
                    else: 
                        self.syscallSummary[k] = {"count": 1, "action": action}
            #return f"jeq #0x{k:08x}({h}), l{self.pc+1+jt:04x}"
            self.last = h
            if action != "": 
                return f"IF {self.current} == {h}: ({action})l{actionno}"
            return f"IF {self.current} == {h}: {self.resolve_action(self.pc+1+jt):0>4}"
        
        
        actionnot = pc+1+jt
        actionnof = pc+1+jf
        actiont = self.resolve_action(actionnot)
        actionf = self.resolve_action(actionnof)
        if self.current == "SYSCALL": 

            if k in SYSCALLS:
                h = SYSCALLS[k][1]
                
                if h in self.syscallSummary.keys():
                    self.syscallSummary[h]["count"] += 1
                    self.syscallSummary[h]["action"] = f"{actiont}/{actionf}"
                else: 
                    
                    self.syscallSummary[h] = {"count": 1, "action": f"{actiont}/{actionf}"}
            else:
                h = f"UnknownSyscall{int(k)}/{hex(k)}"
                
                if h in self.syscallSummary.keys():
                    self.syscallSummary[h]["count"] += 1
                    self.syscallSummary[h]["action"] = f"{actiont} / {actionf}"
                else: 
                    self.syscallSummary[h] = {"count": 1, "action": f"{actiont}/{actionf}"}
        
        return f"IF {self.current} == {h} then {actiont} else {actionf}"
    def op_jmp_set_k(self, jt, jf, k):
        if jf == 0:
            return "jset #0x%x, l%d" % (k, self.pc+1+jt)
        return "jset #0x%x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_gt_x(self, jt, jf):
        if jt == 0:
            return "jle x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jgt x, l%d" % (k, self.pc+1+jt)
        return "jgt x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_ge_x(self, jt, jf):
        if jt == 0:
            return "jlt x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jge x, l%d" % (k, self.pc+1+jt)
        return "jge x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_eq_x(self, jt, jf):
        if jt == 0:
            return "jneq x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jeq x, l%d" % (k, self.pc+1+jt)
        return "jeq x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_set_x(self, jt, jf):
        if jf == 0:
            return "jset x, l%d" % (k, self.pc+1+jt)
        return "jset x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
