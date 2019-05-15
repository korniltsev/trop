import requests # todo replace with urllib
from os.path import expanduser
import subprocess
import os
import re
import struct

download_urls = {
    'x64': 'https://github.com/0vercl0k/rp/releases/download/v2-beta/rp-lin-x64'
}
bin = expanduser("~") + "/.rp++"
def download(url, file):
    if os.path.exists(file):
        return
    content = requests.get(url).content
    with open(file, "wb") as f:
        f.write(content)
    os.system("chmod +x " + file)


class TROP:
    chain = ""
    def __init__(self, binary):
        download(download_urls['x64'], bin) ## todo detect platform & arch
        cmd = bin + " -f " + binary + " -r " + ' 2 --unique ' # todo detect binary arch
        regs = {}
        self.regs = regs
        self.code = ["rop = ''"]
        self.payload = ""
        res = subprocess.check_output(["bash", "-c", cmd])
        for i in re.findall("(0x[a-z0-9]+):(.*;)", res):
            addr = i[0]
            instructions = [it.strip() for it in i[1].split(";")]
            instructions.remove("")
            if len(instructions) == 2 and 'ret' == instructions[1]:
                pops = re.findall("pop (\S+)", instructions[0])
                syscal = re.findall("syscal", instructions[0])

                if len(pops) > 0 and not pops[0] in regs:
                    regs[pops[0]] = {
                        'addr' : addr,
                        'instruction': i[1]
                    }
                if len(syscal) > 0 and not "syscal" in regs:
                    regs['syscall'] = {
                        'addr' : addr,
                        'instruction': i[1]
                    }


    def chain(self):
        return self.payload

    def get_code(self):
        return "\n".join(self.code)

    def reg(self, reg, value):
        print 'reg', reg, hex(value)
        assert type(value) == long or type(value) == int
        assert type(reg) == str
        it = self.regs[reg]
        addr = it['addr']
        self.payload += struct.pack("Q", int(addr, 16))
        self.payload += struct.pack("Q", value)
        code = 'rop += struct.pack("Q", ' + addr + ")"
        commend = '# %s' % it['instruction']
        self.code += ["%-40s %s" %(code, commend)]
        self.code += ['rop += struct.pack("Q", ' + hex(value)+ ")"]

    def syscall(self, *args):
        if len(args) > 0:
            reglist = ['rax', 'rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
            if len(args) > len(reglist):
                raise Exception("unsupported")
            for i in range(len(args)):
                it = args[i]
                reg = reglist[i]
                self.reg(reg, it)

        it = self.regs['syscall']
        addr = it['addr']
        self.payload += struct.pack("Q", int(addr, 16))
        code = 'rop += struct.pack("Q", ' + addr + ")"
        commend = '# %s' % it['instruction']
        self.code += ["%-40s %s" % (code, commend)]

    def jump(self, addr):
        assert type(addr) == long or type(addr) == int
        self.payload += struct.pack("Q", addr)
        code = 'rop += struct.pack("Q", ' + hex(addr) + ")"
        commend = '#  jmp %s' % hex(addr)
        self.code += ["%-40s %s" % (code, commend)]

