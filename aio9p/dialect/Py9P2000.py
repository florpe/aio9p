# pylint: disable=invalid-name
'''
An abstract class for the base 9P2000 protocol. The individual
parser-formatters are provided as functions instead of methods
to enable reuse by other versions of the protocol.
'''

from typing import Any, Tuple, Callable, Coroutine

import aio9p.constant as c
from aio9p.helper import (
    extract
    , extract_bytefields
    , mkfield
    , mkbytefields
    , FieldsT
    , MsgT
    , NULL_LOGGER
    )
from aio9p.protocol import Py9P
from aio9p.stat import Py9P2000Stat

class Py9P2000(Py9P):
    '''
    The main abstract class. Implementations should subclass this.
    '''
    _versionstring = b'9P2000'
    _logger = NULL_LOGGER
    def __init__(self, maxsize, *_, logger=None, **__):
        '''
        Minimal setup.
        '''
        if logger is not None:
            self._logger = logger
        self.maxsize = maxsize
        return None
    async def process_msg(self, msgtype: int, msgbody: bytes) -> MsgT: # pylint: disable=too-many-branches
        '''
        The central dispatch method.
        '''
        self._logger.debug('Processing: %s %s %s', msgtype, c.TRNAME.get(msgtype), msgbody.hex())
        if msgtype == c.TVERSION:
            res = await p9version(self.version, msgbody)
        elif msgtype == c.TAUTH:
            res = await p9auth(self.auth, msgbody)
        elif msgtype == c.TATTACH:
            res = await p9attach(self.attach, msgbody)
        elif msgtype == c.TSTAT:
            res = await p9stat(self.stat, msgbody)
        elif msgtype == c.TCLUNK:
            res = await p9clunk(self.clunk, msgbody)
        elif msgtype == c.TWALK:
            res = await p9walk(self.walk, msgbody)
        elif msgtype == c.TOPEN:
            res = await p9open(self.open, msgbody)
        elif msgtype == c.TREAD:
            res = await p9read(self.read, msgbody)
        elif msgtype == c.TWRITE:
            res = await p9write(self.write, msgbody)
        elif msgtype == c.TCREATE:
            res = await p9create(self.create, msgbody)
        elif msgtype == c.TWSTAT:
            res = await p9wstat(self.wstat, msgbody)
        elif msgtype == c.TREMOVE:
            res = await p9remove(self.remove, msgbody)
        else:
            raise NotImplementedError(msgtype, c.TRNAME.get(msgtype))
        self._logger.debug('Replying with message: %s %s', c.TRNAME.get(res[0]), res)
        return res
    async def version(self, clientmax: int, clientver: bytes):
        '''
        A default version implementation that properly sets self.maxsize.
        Returns None on version mismatch.
        '''
        self.maxsize = min(clientmax, self.maxsize)
        srvver = clientver if clientver == self._versionstring else None
        return self.maxsize, srvver
    async def auth(self, afid: bytes, uname: bytes, aname: bytes) -> bytes:
        '''
        Abstract auth method.
        '''
        raise NotImplementedError
    async def attach(self, fid: bytes, afid: bytes, uname: bytes, aname: bytes) -> bytes:
        '''
        Abstract attach method.
        '''
        raise NotImplementedError
    async def stat(self, fid: bytes) -> Py9P2000Stat:
        '''
        Abstract stat method.
        '''
        raise NotImplementedError
    async def clunk(self, fid: bytes) -> None:
        '''
        Abstract clunk method.
        '''
        raise NotImplementedError
    async def walk(self, fid: bytes, newfid: bytes, wnames: FieldsT) -> FieldsT:
        '''
        Abstract walk method.
        '''
        raise NotImplementedError
    async def open(self, fid: bytes, mode: int) -> Tuple[bytes, int]:
        '''
        Abstract open method.
        '''
        raise NotImplementedError
    async def read(self, fid: bytes, offset: int, count: int) -> bytes:
        '''
        Abstract read method.
        '''
        raise NotImplementedError
    async def write(self, fid: bytes, offset: int, data: bytes) -> int:
        '''
        Abstract write method.
        '''
        raise NotImplementedError
    async def create(
        self
        , fid: bytes
        , name: bytes
        , perm: int
        , mode: int
        ) -> Tuple[bytes, int]:
        '''
        Abstract create method.
        '''
        raise NotImplementedError
    async def wstat(self, fid: bytes, stat: Py9P2000Stat) -> None:
        '''
        Abstract wstat method.
        '''
        raise NotImplementedError
    async def remove(self, fid: bytes) -> None:
        '''
        Abstract remove method.
        '''
        raise NotImplementedError

def p9error(data: bytes) -> MsgT:
    '''
    Format data as an error reply. For the Linux 9p driver it is better to use
    the 9P2000.u format which includes an additional errno field after the
    message.
    '''
    return c.RERROR, *mkbytefields(data)

async def p9version(
    func: Callable[[int, bytes], Coroutine[Any, Any, Tuple[int, bytes]]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    VERSION parser and formatter. Checks that the server version is a prefix
    of the client version, otherwise returns version 'unknown' as demanded by
    the spec.
    '''
    maxsize = extract(msgbody, 0, 4)
    versionlength = extract(msgbody, 4, 2)
    version = msgbody[6:6+versionlength]
    srvmax, srvver = await func(maxsize, version)
    if srvver is None or not version.startswith(srvver):
        srvver = b'unknown'
    srvverlen, srvverfields = mkbytefields(srvver)
    return c.RVERSION, 4 + srvverlen, (mkfield(srvmax, 4),) + srvverfields

def ct_p9version(clientmax: int, clientver: bytes) -> MsgT:
    '''
    Create a TVERSION message body.
    '''
    cverlen, cverfields = mkbytefields(clientver)
    return c.RVERSION, 4 + cverlen, (mkfield(clientmax, 4),) + cverfields

def pr_p9version(msgbody: bytes) -> Tuple[int, bytes]:
    '''
    Parse an RVERSION message body.
    '''
    srvverlen = extract(msgbody, 4, 2)
    return (extract(msgbody, 0, 4), msgbody[6:6+srvverlen])

async def p9attach(
    func: Callable[[bytes, bytes, bytes, bytes], Coroutine[Any, Any, bytes]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    ATTACH parser and formatter.
    '''
    fid = msgbody[0:4]
    afid = msgbody[4:8]
    unamelen = extract(msgbody, 8, 2)
    uname = msgbody[10:10+unamelen]

    anamelen = extract(msgbody, 10+unamelen, 2)
    aname = msgbody[12+unamelen:12+unamelen+anamelen]
    qid = await func(fid, afid, uname, aname)
    return c.RATTACH, 13, (qid,)

def ct_p9attach(fid: bytes, afid: bytes, uname: bytes, aname: bytes) -> MsgT:
    '''
    Create a TATTACH message body.
    '''
    bflen, bflds = mkbytefields(uname, aname)
    return c.TATTACH, 8 + bflen, (
        fid
        , afid
        ) + bflds

def pr_p9attach(msgbody: bytes) -> bytes:
    '''
    Parse an RATTACH message body.
    '''
    return msgbody[:13]

async def p9auth(
    func: Callable[[bytes, bytes, bytes], Coroutine[Any, Any, bytes]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    AUTH parser and formatter.
    '''
    afid = msgbody[0:4]
    unamelen = extract(msgbody, 4, 2)
    uname = msgbody[6:6+unamelen]
    anamelen = extract(msgbody, 6+unamelen, 2)
    aname = msgbody[8+unamelen:8+unamelen+anamelen]
    aqid = await func(afid, uname, aname)
    return c.RAUTH, 13, (aqid,)

def ct_p9auth(fid: bytes, uname: bytes, aname: bytes) -> MsgT:
    '''
    Create a TAUTH message body.
    '''
    bflen, bflds = mkbytefields(uname, aname)
    return c.TAUTH, 8 + bflen, (fid,) + bflds

def pr_p9auth(msgbody: bytes) -> bytes:
    '''
    Parse an RAUTH message body.
    '''
    return msgbody[:13]

async def p9stat(
    func: Callable[[bytes], Coroutine[Any, Any, Py9P2000Stat]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    STAT parser and formatter.
    '''
    fid = msgbody[0:4]
    stat = await func(fid)
    statbytes = stat.to_bytes(with_envelope=True)
    return c.RSTAT, len(statbytes), (statbytes,)

def ct_p9stat(fid: bytes) -> MsgT:
    '''
    Create a TSTAT message body.
    '''
    return c.TSTAT, 4, (fid,)

def pr_p9stat(msgbody: bytes) -> Py9P2000Stat:
    '''
    Parse an RSTAT message body.
    '''
#    statlen = extract(msgbody, 0, 2)
    return Py9P2000Stat.from_bytes(msgbody, 2)

async def p9clunk(
    func: Callable[[bytes], Coroutine[Any, Any, None]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    CLUNK parser and formatter.
    '''
    fid = msgbody[0:4]
    await func(fid)
    return c.RCLUNK, 0, ()

def ct_p9clunk(fid: bytes) -> MsgT:
    '''
    Create a TCLUNK message body.
    '''
    return c.TCLUNK, 4, (fid,)

def pr_p9clunk(_: bytes) -> None:
    '''
    Parse an RVERSION message body.
    '''
    return None

async def p9walk(
    func: Callable[[bytes, bytes, FieldsT], Coroutine[Any, Any, FieldsT]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    WALK parser and formatter.
    '''
    fid = msgbody[0:4]
    newfid = msgbody[4:8]
    count = extract(msgbody, 8, 2)
    try:
        wnames = extract_bytefields(msgbody, 10, count)
    except ValueError as e:
        raise ValueError('Could not build walknames', count, msgbody[10:].hex()) from e
    qids = await func(fid, newfid, wnames)
    if count and not qids:
        errmsg = b'No such file!'
        errenvelope = mkfield(13, 2)
        return c.RERROR, 15, (errenvelope, errmsg)
    qidcount = len(qids)
    return c.RWALK, 2 + 13*qidcount, (mkfield(qidcount, 2),) + qids

def ct_p9walk(fid: bytes, newfid: bytes, wnames: Tuple[bytes]) -> MsgT:
    '''
    Create a TWALK message body.
    '''
    wnamelen, wnamefields = mkbytefields(*wnames)
    return c.TWALK, 10 + wnamelen, (
        fid
        , mkfield(newfid, 4)
        , mkfield(len(wnames), 2)
        ) + wnamefields

def pr_p9walk(msgbody: bytes) -> Tuple[bytes]:
    '''
    Parse an RWALK message body.
    '''
    qidcount = extract(msgbody, 0, 2)
    return tuple(
        msgbody[2+offset,15+offset]
        for offset in range(0, 13*qidcount, 13)
        )

async def p9open(
    func: Callable[[bytes, int], Coroutine[Any, Any, Tuple[bytes, int]]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    OPEN parser and formatter.
    '''
    fid = msgbody[0:4]
    mode = extract(msgbody, 4, 1)
    qid, iounit = await func(fid, mode)
    return c.ROPEN, 17, (qid, mkfield(iounit, 4))

def ct_p9open(fid: bytes, mode: int) -> MsgT:
    '''
    Create a TOPEN message body.
    '''
    return c.TWALK, 5, (
        fid
        , mkfield(mode, 1)
        )

def pr_p9open(msgbody: bytes) -> Tuple[bytes, int]:
    '''
    Parse an ROPEN message body.
    '''
    return msgbody[:13], extract(msgbody, 13, 4)

async def p9read(
    func: Callable[[bytes, int, int], Coroutine[Any, Any, bytes]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    READ parser and formatter.
    '''
    fid = msgbody[0:4]
    offset = extract(msgbody, 4, 8)
    count = extract(msgbody, 12, 4)
    resdata = await func(fid, offset, count)
    resdatalen = len(resdata)
    return c.RREAD, 4 + resdatalen, (mkfield(resdatalen, 4), resdata)

def ct_p9read(fid: bytes, offset: int, count: int) -> MsgT:
    '''
    Create a TREAD message body.
    '''
    return c.TREAD, 16, (
        fid
        , mkfield(offset, 8)
        , mkfield(count, 4)
        )

def pr_p9read(msgbody: bytes) -> Tuple[bytes, int]:
    '''
    Parse an RREAD message body.
    '''
    return msgbody[:13], extract(msgbody, 13, 4)

async def p9write(
    func: Callable[[bytes, int, bytes], Coroutine[Any, Any, int]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    WRITE parser and formatter.
    '''
    fid = msgbody[0:4]
    offset = extract(msgbody, 4, 8)
    count = extract(msgbody, 12, 4)
    data = msgbody[16:16+count]
    rescount = await func(fid, offset, data)
    return c.RWRITE, 4, (mkfield(rescount, 4),)

def ct_p9write(fid: bytes, offset: int, data: bytes) -> MsgT:
    '''
    Create a TWRITE message body.
    '''
    datalen = len(data)
    return c.TWRITE, 16 + datalen, (
        fid
        , mkfield(offset, 8)
        , mkfield(datalen, 4)
        , data
        )

def pr_p9write(msgbody: bytes) -> int:
    '''
    Parse an RWRITE message body.
    '''
    return extract(msgbody, 0, 4)

async def p9create(
    func: Callable[[bytes, bytes, int, int], Coroutine[Any, Any, Tuple[bytes, int]]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    CREATE parser and formatter.
    '''
    fid = msgbody[0:4]
    namelen = extract(msgbody, 4, 2)
    name = msgbody[6:6+namelen]

    perm = extract(msgbody, 6+namelen, 4)
    mode = extract(msgbody, 10+namelen, 1)
    qid, iounit = await func(fid, name, perm, mode)
    return c.RCREATE, 17, (qid, mkfield(iounit, 4))

def ct_p9create(fid: bytes, name: bytes, perm: int, mode: int) -> MsgT:
    '''
    Create a TWRITE message body.
    '''
    namelen, namefields = mkbytefields(name)
    return c.TWRITE, 10 + namelen, (
        fid
        , *namefields
        , mkfield(perm, 4)
        , mkfield(mode, 1)
        )

def pr_p9create(msgbody: bytes) -> Tuple[bytes, int]:
    '''
    Parse an RWRITE message body.
    '''
    return msgbody[:13], extract(msgbody, 13, 4)

async def p9wstat(
    func: Callable[[bytes, Py9P2000Stat], Coroutine[Any, Any, None]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    WSTAT parser and formatter.
    '''
    fid = msgbody[0:4]
    stat = Py9P2000Stat.from_bytes(msgbody, 6)
    await func(fid, stat)
    return c.RWSTAT, 0, ()

def ct_p9wstat(fid: bytes, stat: Py9P2000Stat) -> MsgT:
    '''
    Create a TWSTAT message.
    '''
    binstat = stat.to_bytes(with_envelope=True)
    return c.TWSTAT, 4 + len(binstat), (fid, binstat)

def pr_p9wstat(_: bytes) -> None:
    '''
    Parse an RWSTAT message.
    '''
    return None

async def p9remove(
    func: Callable[[bytes], Coroutine[Any, Any, None]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    REMOVE parser and formatter.
    '''
    fid = msgbody[0:4]
    await func(fid)
    return c.RREMOVE, 0, ()

def ct_p9remove(fid: bytes) -> MsgT:
    '''
    Create a TREMOVE message.
    '''
    return c.TREMOVE, 4, (fid,)

def pr_p9remove(_: bytes) -> None:
    '''
    Parse an RREMOVE message.
    '''
    return None
