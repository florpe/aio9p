
from itertools import chain

from aio9p.constant import ENCODING

def mkqid(mode, base, version=0):
    if isinstance(base, int):
        base = base.to_bytes(8, 'little')
    return b''.join((
        (mode >> 24).to_bytes(1, 'little')
        , version.to_bytes(4, 'little')
        , base
        ))

def extract(msg, offset, size):
    return int.from_bytes(msg[offset:offset+size], byteorder='little')

def extract_bytefields(msg, offset, count):
    return tuple(_gen_bytefields(msg, offset, count))

def _gen_bytefields(msg, offset, count):
    msglen = len(msg)
    while count > 0:
        print(f'{msglen=} {count=} {offset=}')
        assert offset + 2 <= msglen
        fieldlen = extract(msg, offset, 2)
        nextoffset = offset + 2 + fieldlen
        print(f'{msglen=} {count=} {offset=} {fieldlen=} {nextoffset=}')
        assert nextoffset <= msglen
        yield msg[offset+2:nextoffset]
        offset = nextoffset
        count = count - 1


def mkfield(value, size):
    try:
        return value.to_bytes(size, byteorder='little')
    except OverflowError as e:
        print('Overflow:', value, size)
        raise ValueError from e

def mkbytefield(*payloads):
    total = sum(2 + len(payload) for payload in payloads)
    resfields = tuple(chain.from_iterable(
        (len(payload).to_bytes(2, byteorder='little'), payload)
        for payload in payloads
        ))
    print(f'Bytefield: {total=} {resfields=}')
    return total, resfields

def mkstrfield(*args):
    return mkbytefield(*(
        value.encode(ENCODING)
        for value in args
        ))

