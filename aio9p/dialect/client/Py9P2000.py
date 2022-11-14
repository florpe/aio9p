# pylint: disable=invalid-name
'''
A 9P2000 client implementation. The individual parser-formatters
are provided as functions instead of methods to enable reuse by
other versions of the protocol.
'''

from typing import Tuple

import aio9p.constant as c
from aio9p.helper import (
    extract
    , mkbytefields
    , mkfield
    )
from aio9p.protocol import Py9PClient
from aio9p.stat import Py9P2000Stat

async def p9_version(
    implementation
    , clientmax: int
    , clientver: bytes
    ) -> Tuple[int, bytes]:
    '''
    TVERSION, RVERSION.
    '''
    cverlen, cverfields = mkbytefields(clientver)
    _, msgbody = await implementation.message(
        (c.TVERSION, 4 + cverlen, (mkfield(clientmax, 4),) + cverfields)
        )
    srvverlen = extract(msgbody, 4, 2)
    return extract(msgbody, 0, 4), msgbody[6:6+srvverlen]

async def p9_attach(
    implementation
    , fid: bytes
    , afid: bytes
    , uname: bytes
    , aname: bytes
    ) -> bytes:
    '''
    Create a TATTACH message body.
    Parse an RATTACH message body.
    '''
    bflen, bflds = mkbytefields(uname, aname)
    _, msgbody = await implementation.message(
        (c.TATTACH, 8 + bflen, (fid, afid) + bflds)
        )
    return msgbody[:13]
async def p9_auth(
    implementation
    , fid: bytes, uname: bytes, aname: bytes
    ) -> bytes:
    '''
    Create a TAUTH message body.
    Parse an RAUTH message body.
    '''
    bflen, bflds = mkbytefields(uname, aname)
    _, msgbody = await implementation.message(
        (c.TAUTH, 8 + bflen, (fid,) + bflds)
        )
    return msgbody[:13]

async def p9_stat(
    implementation
    , fid: bytes
    ) -> Py9P2000Stat:
    '''
    Create a TSTAT message body.
    Parse an RSTAT message body.
    '''
    _, msgbody = await implementation.message(
        (c.TSTAT, 4, (fid,))
        )
#    statlen = extract(msgbody, 0, 2)
    return Py9P2000Stat.from_bytes(msgbody, 2)

async def p9_clunk(
    implementation
    , fid: bytes
    ) -> None:
    '''
    Create a TCLUNK message body.
    Parse an RVERSION message body.
    '''
    await implementation.message(
        (c.TCLUNK, 4, (fid,))
        )
    return None

async def p9_walk(
    implementation
    , fid: bytes, newfid: bytes, wnames: Tuple[bytes]
    ) -> Tuple[bytes, ...]:
    '''
    Create a TWALK message body.
    Parse an RWALK message body.
    '''
    wnamelen, wnamefields = mkbytefields(*wnames)
    fields = (
        fid
        , newfid
        , mkfield(len(wnames), 2)
        )  + wnamefields
    _, msgbody = await implementation.message(
        (c.TWALK, 10 + wnamelen, fields)
        )
    qidcount = extract(msgbody, 0, 2)
    return tuple(
        msgbody[2+offset:15+offset]
        for offset in range(0, 13*qidcount, 13)
        )

async def p9_open(
    implementation
    , fid: bytes, mode: int
    ) -> Tuple[bytes, int]:
    '''
    Create a TOPEN message body.
    Parse an ROPEN message body.
    '''
    _, msgbody = await implementation.message(
        (c.TWALK, 5, (fid, mkfield(mode, 1)))
        )
    return msgbody[:13], extract(msgbody, 13, 4)

async def p9_read(
    implementation
    , fid: bytes, offset: int, count: int
    ) -> Tuple[bytes, int]:
    '''
    Create a TREAD message body.
    Parse an RREAD message body.
    '''
    _, msgbody = await implementation.message(
        (c.TREAD, 16, (fid, mkfield(offset, 8), mkfield(count, 4)))
        )
    return msgbody[:13], extract(msgbody, 13, 4)

async def p9_write(
    implementation
    , fid: bytes, offset: int, data: bytes
    ) -> int:
    '''
    Create a TWRITE message body.
    Parse an RWRITE message body.
    '''
    datalen = len(data)
    fields = (
        fid
        , mkfield(offset, 8)
        , mkfield(datalen, 4)
        , data
        )
    _, msgbody = await implementation.message(
        (c.TWRITE, 16 + datalen, fields)
        )
    return extract(msgbody, 0, 4)

async def p9_create(
    implementation
    , fid: bytes, name: bytes, perm: int, mode: int
    ) -> Tuple[bytes, int]:
    '''
    Create a TWRITE message body.
    Parse an RWRITE message body.
    '''
    namelen, namefields = mkbytefields(name)
    fields = (fid, *namefields, mkfield(perm, 4), mkfield(mode, 1))
    _, msgbody = await implementation.message(
        (c.TWRITE, 10 + namelen, fields)
        )
    return msgbody[:13], extract(msgbody, 13, 4)

async def p9_wstat(
    implementation
    , fid: bytes
    , stat: Py9P2000Stat
    ) -> None:
    '''
    Create a TWSTAT message.
    Parse an RWSTAT message.
    '''
    binstat = stat.to_bytes(with_envelope=True)
    await implementation.message(
        (c.TWSTAT, 4 + len(binstat), (fid, binstat))
        )
    return None

async def p9_remove(
    implementation
    , fid: bytes
    ) -> None:
    '''
    Create a TREMOVE message.
    Parse an RREMOVE message.
    '''
    await implementation.message(
        (c.TREMOVE, 4, (fid,))
        )
    return None

class Py9P2000Client(Py9PClient): # pylint: disable=too-many-instance-attributes,too-few-public-methods
    '''
    A client for the 9P2000 dialect.
    '''
    versionstring = b'9P2000'
    version = p9_version
    attach = p9_attach
    auth = p9_auth
    stat = p9_stat
    clunk = p9_clunk
    walk = p9_walk
    open = p9_open
    read = p9_read
    write = p9_write
    create = p9_create
    wstat = p9_wstat
    remove = p9_remove
