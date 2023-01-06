
'''
Various utility functions and values:
    - Parsers and formatters
    - Types
    - The default NULL logger
'''

from itertools import chain
from logging import getLogger, NullHandler
from typing import Union, Tuple, Generator

from aio9p.constant import ENCODING

FieldsT = Union[Tuple[()], Tuple[bytes, ...]]
MsgT = Tuple[int, int, FieldsT]
RspT = Tuple[int, bytes]

NULL_LOGGER = getLogger('')
NULL_LOGGER.setLevel('CRITICAL')
NULL_LOGGER.addHandler(NullHandler())

def mkqid(mode: int, base: Union[int, bytes], version: int = 0) -> bytes:
    '''
    Create a qid from a base reference, a mode, and an optional version.
    '''
    if isinstance(base, int):
        base = base.to_bytes(8, 'little')
    return b''.join((
        (mode >> 24).to_bytes(1, 'little')
        , version.to_bytes(4, 'little')
        , base
        ))

def extract(msg: bytes, offset: int, size: int) -> int:
    '''
    Extract the field of size size at offset offset as a little-endian integer.
    '''
    return int.from_bytes(msg[offset:offset+size], byteorder='little')

def extract_bytefields(msg: bytes, offset: int, count: int) -> Tuple[bytes, ...]:
    '''
    Extract count bytefields starting at offset offset.
    '''
    return tuple(_gen_bytefields(msg, offset, count))

def _gen_bytefields(msg: bytes, offset: int, count: int) -> Generator[bytes, None, None]:
    '''
    The generator version of extract_bytefields.
    '''
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


def mkfield(value: int, size: int) -> bytes:
    '''
    Format the value value into a little-endian field of size size.
    '''
    try:
        return value.to_bytes(size, byteorder='little')
    except (AttributeError, OverflowError, ValueError) as e:
        raise ValueError('Failed to convert field', value, size) from e

def mkbytefields(*payloads: bytes) -> Tuple[int, FieldsT]:
    '''
    Equip the arguments with the two-byte length envelopes mandated by 9P.
    Returns the total length and a tuple of the resulting fields. Does not join
    envelopes with their contents - the length of the result tuple is twice the
    argument count.
    '''
    total = sum((2 + len(payload) for payload in payloads))
    resfields = tuple(chain.from_iterable(
        (len(payload).to_bytes(2, byteorder='little'), payload)
        for payload in payloads
        ))
    return total, resfields

def mkstrfields(*args: str) -> Tuple[int, FieldsT]:
    '''
    Like mkbytefields, but applies UTF-8 formatting.
    '''
    return mkbytefields(*(
        value.encode(ENCODING)
        for value in args
        ))
