Trivial rop builder.
You probably don't want it.

Sample:
import trop
t = trop.TROP("speedrun-008")
t.syscall(10, 0x400000, 100, 7)
t.syscall(0, 0, 0x400000, 100)
t.jump(0x400000)
rop = t.chain()
