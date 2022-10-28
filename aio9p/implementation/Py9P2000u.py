# pylint: disable=invalid-name,duplicate-code
'''
An abstract class for the base 9P2000 protocol.
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
from aio9p.implementation.Py9P2000 import (
    p9version
    #    , p9auth
    #    , p9attach
    #    , p9stat
    , p9clunk
    , p9walk
    , p9open
    , p9read
    , p9write
    #    , p9wstat
    , p9remove
    )
from aio9p.protocol import Py9P
from aio9p.stat import Py9P2000uStat


class Py9P2000u(Py9P):
    '''
    The main abstract class. Implementations should subclass this. This class
    is not a subclass of Py9P2000 to avoid making Py9P2000uStat a subclass of
    Py9P2000Stat.
    The default versioning behaviour is not to fall back to a degraded 9P2000
    mode.
    '''
    _versionstring = b'9P2000.u'
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
    async def version(self, clientmax: int, _: bytes):
        '''
        A default version implementation that properly sets self.maxsize.
        '''
        self.maxsize = min(clientmax, self.maxsize)
        return self.maxsize, self._versionstring
    async def auth(self, afid: bytes, uname: bytes, aname: bytes, n_uname: int) -> bytes:
        '''
        Abstract auth method.
        '''
        raise NotImplementedError
    async def attach( # pylint: disable=too-many-arguments
        self
        , fid: bytes
        , afid: bytes
        , uname: bytes
        , aname: bytes
        , n_uname: int
        ) -> bytes:
        '''
        Abstract attach method.
        '''
        raise NotImplementedError
    async def stat(self, fid: bytes) -> Py9P2000uStat:
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
    async def create( # pylint: disable=too-many-arguments
        self
        , fid: bytes
        , name: bytes
        , perm: int
        , mode: int
        , extension: bytes
        ) -> Tuple[bytes, int]:
        '''
        Abstract create method.
        '''
        raise NotImplementedError
    async def wstat(self, fid: bytes, stat: Py9P2000uStat) -> None:
        '''
        Abstract wstat method.
        '''
        raise NotImplementedError
    async def remove(self, fid: bytes) -> None:
        '''
        Abstract remove method.
        '''
        raise NotImplementedError

def p9error(data: bytes, errno: int) -> MsgT:
    '''
    Format data as an error reply.
    '''
    msglen, msgfields = mkbytefields(data)
    return c.RERROR, msglen + 4, msgfields + (mkfield(errno, 4),)

async def p9attach(
    func: Callable[[bytes, bytes, bytes, bytes, int], Coroutine[Any, Any, bytes]]
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
    n_uname = extract(msgbody, 12+unamelen+anamelen, 4)
    qid = await func(fid, afid, uname, aname, n_uname)
    return c.RATTACH, 13, (qid,)

async def p9auth(
    func: Callable[[bytes, bytes, bytes, int], Coroutine[Any, Any, bytes]]
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
    n_uname = extract(msgbody, 8+unamelen+anamelen, 4)
    aqid = await func(afid, uname, aname, n_uname)
    return c.RAUTH, 13, (aqid,)

async def p9stat(
    func: Callable[[bytes], Coroutine[Any, Any, Py9P2000uStat]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    STAT parser and formatter.
    '''
    fid = msgbody[0:4]
    stat = await func(fid)
    statbytes = stat.to_bytes(with_envelope=True)
    return c.RSTAT, len(statbytes), (statbytes,)

async def p9create(
    func: Callable[[bytes, bytes, int, int, bytes], Coroutine[Any, Any, Tuple[bytes, int]]]
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
    (extension,) = extract_bytefields(msgbody, 11+namelen, 1)
    qid, iounit = await func(fid, name, perm, mode, extension)
    return c.RCREATE, 17, (qid, mkfield(iounit, 4))

async def p9wstat(
    func: Callable[[bytes, Py9P2000uStat], Coroutine[Any, Any, None]]
    , msgbody: bytes
    ) -> MsgT:
    '''
    WSTAT parser and formatter.
    '''
    fid = msgbody[0:4]
    stat = Py9P2000uStat.from_bytes(msgbody, 6)
    await func(fid, stat)
    return c.RWSTAT, 0, ()
