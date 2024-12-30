import re
import ply.yacc as yacc

from pybpf.assembler import BPFLexer

INT = r'(0x[0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)'
SPACE = r'\s+'

class CParser(object):
    def p_program(self, p):
        """ program : instr_list
                    | instr_list ',' """
        p[0] = p[1]

    def p_instr_list_start(self, p):
        """ instr_list : instr """
        p[0] = [p[1]]

    def p_instr_list(self, p):
        """ instr_list : instr_list ',' instr """
        p[0] = p[1] + [p[3]]

    def p_instr(self, p):
        """ instr : '{' NUMBER ',' NUMBER ',' NUMBER ',' NUMBER '}' """
        p[0] = (p[2], p[4], p[6], p[8])

    def p_recover(self, p):
        """ instr : error '}' """

    tokens = ('NUMBER',)

    def p_error(self, p):
        if p is None:
            print "Syntax error at end of file"
        else:
            print "Syntax error: Unpected token %s on line %d" % (p.type, p.lineno)
        self.errors += 1

    def build(self):
        self.lexer = BPFLexer()
        self.lexer.build()
        self.parser = yacc.yacc(module=self, debug=False)

    def parse(self, data, debug=False):
        self.errors = 0
        prog = self.parser.parse(data, lexer=self.lexer, debug=debug)
        if self.errors or self.lexer.errors:
            return None
        return prog


class BPFReader(object):
    def read(self, file):
        data = file.read()
        prog = []

        if re.match('^\s*\d+\s*,', data):
            # One line output, from bpfc
            fields = data.strip(" ,\t\n").split(',')

            proglen = int(fields.pop(0))
            if proglen != len(fields):
                raise Exception('Length field incorrect')

            pat = re.compile('^' + INT + SPACE + INT + SPACE + INT + SPACE + INT + '$')
            for lineno, line in enumerate(fields):
                m = pat.match(line.strip())
                if not m:
                    raise Exception('Invalid format at instruction %d' % lineno)
                instr = tuple(int(i) for i in m.groups())
                prog.append(instr)

        elif re.match(r'^\s*\{\s*' + INT, data):
            # C style output
            parser = CParser()
            parser.build()

            prog = parser.parse(data)
            if prog is None:
                raise Exception('Parse failure')

        for instr in prog:
            if not 0 <= instr[0] < 256 or \
                    not 0 <= instr[1] < 256 or \
                    not 0 <= instr[2] < 256 or \
                    not 0 <= instr[3] <= 0xFFFFFFFF:
                raise Exception('Invalid number at instruction %d' % lineno)

        return prog
