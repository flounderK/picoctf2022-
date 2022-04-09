#!/usr/bin/env python3
import re


def batch(it, sz):
    length = len(it)
    for i in range(0, length, sz):
        yield it[i:i+sz]


with open('game', 'rb') as f:
    c = f.read()


a = [i for i in re.findall(b'[.# >@]+', c) if len(i) > 16]
for bitmap in a:
    for line in batch(bitmap.decode(), 100):
        print(line)

