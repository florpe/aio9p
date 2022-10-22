
from itertools import chain
from logging import getLogger, NullHandler

from aio9p.constant import ENCODING

NULL_LOGGER = getLogger('')
NULL_LOGGER.setLevel('DEBUG')
NULL_LOGGER.addHandler(NullHandler())

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
        if msglen < offset + 2:
            raise ValueError('Incomplete length field', msg, offset)
        fieldlen = extract(msg, offset, 2)
        nextoffset = offset + 2 + fieldlen
        if msglen < nextoffset:
            raise ValueError('Incomplete content field', msg, offset)
        yield msg[offset+2:nextoffset]
        offset = nextoffset
        count = count - 1


def mkfield(value, size):
    try:
        return value.to_bytes(size, byteorder='little')
    except OverflowError as e:
        raise ValueError from e

def mkbytefield(*payloads): #TODO: Rename to mkbytefields
    total = sum(2 + len(payload) for payload in payloads)
    resfields = tuple(chain.from_iterable(
        (len(payload).to_bytes(2, byteorder='little'), payload)
        for payload in payloads
        ))
    return total, resfields

def mkstrfield(*args): #TODO: Rename to mkstrfields
    return mkbytefield(*(
        value.encode(ENCODING)
        for value in args
        ))

