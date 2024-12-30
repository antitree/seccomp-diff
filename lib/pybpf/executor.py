from pybpf.disassembler import BPFDecoder
from pybpf.disassembler import BPFDisassembler


class BPFExecutor(BPFDecoder):
    def set_program(self, prog):
        """ Set program as list of 4-tuples """
        self.prog = prog

    def start(self, packet):
        self.a = self.x = 0
        self.m = [0] * 16
        self.pc = 0
        self.retval = None
        self.packet = bytearray(packet)

    def step(self):
        if self.retval is not None:
            return False

        op, jt, jf, k = self.prog[self.pc]
        self.pc += 1
        self.decode_one(op, jt, jf, k)

        return self.retval is None

    def stop(self):
        return self.retval

    def run(self, packet):
        self.start(packet)
        while self.step():
            pass
        return self.stop()

    def op_set_a_imm(self, k):
        self.a = k

    def op_set_a_mem(self, k):
        self.a = self.m[k]

    def op_set_a_abs(self, k, size):
        if size == 1:
            self.a = self.packet[k]
        if size == 2:
            self.a = self.packet[k] * 256 + self.packet[k+1]
        if size == 4:
            self.a = ((self.packet[k] * 256 + self.packet[k+1]) * 256 + self.packet[k+2]) * 256 + self.packet[k+3]

    def op_set_a_ind(self, k, size):
        self.op_set_a_abs(self.x + k, size)

    def op_set_x_imm(self, k):
        self.x = k

    def op_set_x_mem(self, k):
        self.x = self.m[k]

    def op_set_x_msh(self, k):
        self.x = (self.packet[k] & 0x0F) * 4

    def op_set_mem_a(self, k):
        self.m[k] = self.a

    def op_set_mem_x(self, k):
        self.m[k] = self.x

    def op_alu_add_k(self, k):
        self.a = (self.a + k) & 0xFFFFFFFF
    def op_alu_sub_k(self, k):
        self.a = (self.a - k) & 0xFFFFFFFF
    def op_alu_mul_k(self, k):
        self.a = (self.a * k) & 0xFFFFFFFF
    def op_alu_div_k(self, k):
        self.a = (self.a // k) & 0xFFFFFFFF
    def op_alu_or_k(self, k):
        self.a |= k
    def op_alu_and_k(self, k):
        self.a &= k
    def op_alu_lsh_k(self, k):
        self.a = (self.a << k) & 0xFFFFFFFF
    def op_alu_rsh_k(self, k):
        self.a >>= k
    def op_alu_neg():
        self.a = -self.a
    def op_alu_mod_k(self, k):
        self.a = (self.a % k) & 0xFFFFFFFF
    def op_alu_xor_k(self, k):
        self.a ^= k

    def op_alu_add_x(self):
        self.a = (self.a + self.x) & 0xFFFFFFFF
    def op_alu_sub_x(self):
        self.a = (self.a - self.x) & 0xFFFFFFFF
    def op_alu_mul_x(self):
        self.a = (self.a * self.x) & 0xFFFFFFFF
    def op_alu_div_x(self):
        self.a = (self.a // self.x) & 0xFFFFFFFF
    def op_alu_or_x(self):
        self.a |= self.x
    def op_alu_and_x(self):
        self.a &= self.x
    def op_alu_lsh_x(self):
        self.a = (self.a << self.x) & 0xFFFFFFFF
    def op_alu_rsh_x(self):
        self.a >>= self.x
    def op_alu_mod_x(self):
        self.a = (self.a % self.x) & 0xFFFFFFFF
    def op_alu_xor_x(self):
        self.a ^= self.x

    def op_ret_k(self, k):
        self.retval = k
    def op_ret_x():
        self.retval = self.x
    def op_ret_a():
        self.retval = self.a

    def op_misc_tax(self):
        self.x = self.a
    def op_misc_txa(self):
        self.a = self.x

    def op_jmp_a(self, k):
        self.pc += k
    def op_jmp_gt_k(self, jt, jf, k):
        self.pc += jt if (self.a > k) else jf
    def op_jmp_ge_k(self, jt, jf, k):
        self.pc += jt if (self.a >= k) else jf
    def op_jmp_eq_k(self, jt, jf, k):
        self.pc += jt if (self.a == k) else jf
    def op_jmp_set_k(self, jt, jf, k):
        self.pc += jt if (self.a & k) else jf
    def op_jmp_gt_x(self, jt, jf):
        self.pc += jt if (self.a > self.x) else jf
    def op_jmp_ge_x(self, jt, jf):
        self.pc += jt if (self.a >= self.x) else jf
    def op_jmp_eq_x(self, jt, jf):
        self.pc += jt if (self.a == self.x) else jf
    def op_jmp_set_x(self, jt, jf):
        self.pc += jt if (self.a & self.x) else jf

class BPFTracer(BPFExecutor):
    def step(self):
        d = BPFDisassembler()
        s = d.disassemble_one(self.pc, self.prog[self.pc])

        print "l%d\t%-24s  A=%08X  X=%08X" % (self.pc, s, self.a, self.x)
        return super(BPFTracer, self).step()
