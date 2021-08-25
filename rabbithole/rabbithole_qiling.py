import sys
from qiling import *
from unicorn import *
from unicorn.x86_const import *
from qiling.os.posix.stat import Fstat

sys.path.append("..")

#Number of correct characters
user_data = [0]

#Pipe class
#Borrowed from qiling/examples/crackme_x86_linux.py
class MyPipe():
    def __init__(self):
        self.buf = b''
    def write(self, s):
        self.buf += s
    def read(self, l):
        if l <= len(self.buf):
            ret = self.buf[ : l]
            self.buf = self.buf[l : ]
        else:
            ret = self.buf
            self.buf = ''
        return ret
    def fileno(self):
        return 0
    def show(self):
        pass
    def clear(self):
        pass
    def flush(self):
        pass
    def close(self):
        self.outpipe.close()
    def fstat(self):
        return Fstat(sys.stdin.fileno())
    
def breakpoint(ql):
    #If RAX == 1 then we have a correct character, otherwise it's false
    eax = ql.uc.reg_read(UC_X86_REG_RAX)
    if eax == 0x1:
        user_data[0] += 1
    
def exec(flag):
    #Reset our counter
    user_data[0] = 0
    
    #Set up pipes for IO
    stdin = MyPipe()
    stdout = MyPipe()
    
    #Initialize ql
    ql = Qiling(["/tmp/rabbithole"], "rootfs/x8664_linux", stdin = stdin, stdout = stdout, stderr = sys.stderr)
    
    #Pass the flag
    stdin.write(bytes("".join(flag) + "\n", 'utf-8'))
    
    #Hook our address at 0x5555555aa218
    #Since the qiling loader uses 0x555555554000 as the load address for 64
    #Reference /qiling/loader/elf.py
    ql.hook_address(breakpoint,0x5555555aa218)
    ql.run()
    
    #Check stdout
    stdout = stdout.read(0x256).decode('utf-8')
    
    #Print status and ret
    print('flag: {}\nstdout: "{}"\ncorrect:{}\n'.format(''.join(flag), stdout, user_data[0]))
    del stdin
    del ql
    return stdout,user_data[0]
    
def solve():
    #Prefix is known
    #Also known is len(prefix + flag) == 54
    prefix = list("flag{")
    flag = list("\x20"*54)
    #Set our best
    _,best = exec(prefix + flag)
    i = 0                   
    try:
        for i in range(len(flag)):
            for j in "_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-{}":
                flag[i] = j
                stdout,correct_chars = exec(prefix + flag)
                if correct_chars > best:
                    best = correct_chars
                    break
    except KeyboardInterrupt:
        print("STOP: KeyboardInterrupt")

solve()
