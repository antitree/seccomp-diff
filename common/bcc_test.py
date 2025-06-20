import bcc
from sockfilter import SockFilter, SockFprog, RUNTIMEDEFAULT
#import default

d = bcc.disassembler.BPFDecoder()
print(dir(d))
yolo = bcc.disassemble_prog(RUNTIMEDEFAULT)
print(yolo)
