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
        if msgtype == c.TVERSION:
            res = await p9_version(self.version, msgbody)
        elif msgtype == c.TAUTH:
            res = await p9_auth(self.auth, msgbody)
        elif msgtype == c.TATTACH:
            res = await p9_attach(self.attach, msgbody)
        elif msgtype == c.TSTAT:
            res = await p9_stat(self.stat, msgbody)
        elif msgtype == c.TCLUNK:
            res = await p9_clunk(self.clunk, msgbody)
        elif msgtype == c.TWALK:
            res = await p9_walk(self.walk, msgbody)
        elif msgtype == c.TOPEN:
            res = await p9_open(self.open, msgbody)
        elif msgtype == c.TREAD:
            res = await p9_read(self.read, msgbody)
        elif msgtype == c.TWRITE:
            res = await p9_write(self.write, msgbody)
        elif msgtype == c.TCREATE:
            res = await p9_create(self.create, msgbody)
        elif msgtype == c.TWSTAT:
            res = await p9_wstat(self.wstat, msgbody)
        elif msgtype == c.TREMOVE:
            res = await p9_remove(self.remove, msgbody)
        else:
            raise NotImplementedError(msgtype, c.TRNAME.get(msgtype))
        self._logger.debug('Replying with message: %s %s', c.TRNAME.get(res[0]), res)
        return res
    def errhandler(self, exception):
        '''
        The base protocol does not support errnos.
        '''
        return p9_error(str(exception).encode('utf-8'))

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

def p9_error(data: bytes) -> MsgT:
    '''
    Format data as an error reply. For the Linux 9p driver it is better to use
    the 9P2000.u format which includes an additional errno field after the
    message.
    '''
    return c.RERROR, *mkbytefields(data)

async def p9_version(
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

async def p9_attach(
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

async def p9_auth(
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

async def p9_stat(
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

async def p9_clunk(
    func: Callable[[bytes], Coroutine[Any, Any, None]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    CLUNK parser and formatter.
    '''
    fid = msgbody[0:4]
    await func(fid)
    return c.RCLUNK, 0, ()

async def p9_walk(
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

async def p9_open(
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

async def p9_read(
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


async def p9_write(
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

async def p9_create(
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

async def p9_wstat(
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

async def p9_remove(
    func: Callable[[bytes], Coroutine[Any, Any, None]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    REMOVE parser and formatter.
    '''
    fid = msgbody[0:4]
    await func(fid)
    return c.RREMOVE, 0, ()
