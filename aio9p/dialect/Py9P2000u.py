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
    , MsgT
    )
from aio9p.dialect.Py9P2000 import (
    Py9P2000
    , p9_version
    )
from aio9p.protocol import Py9PException
from aio9p.stat import Py9P2000uStat

MODIFIED_MESSAGE_TYPES = {c.TVERSION, c.TAUTH, c.TATTACH, c.TSTAT, c.TCREATE, c.TWSTAT}

class Py9P2000u_Exception(Py9PException):
    '''
    Mandatory errnos.
    '''
    def __init__(self, errno, *args, **kwargs):
        '''
        Sets errno and kwargs as attributes.
        '''
        super().__init__(self, errno, *args, **kwargs)
        for k, kwarg in kwargs.items():
            setattr(self, k, kwarg)
        self.errno = errno
        self.args = tuple(errno, *args)
        return None

class Py9P2000u(Py9P2000):
    '''
    The main abstract class. Implementations should subclass this. The methods
    that differ from `Py9P2000` carry the `_u` suffix.
    The default versioning behaviour is not to fall back to a degraded 9P2000
    mode. If such a fallback is desired, implement the non-suffixed methods
    and set `offer_fallback_to_9P2000` - the `version` method will detect
    requests for the plain `9P2000` protocol and set `fallback_to_9P2000`
    accordingly.
    '''

    offer_fallback_to_9P2000 = False
    fallback_to_9P2000 = False
    _versionstring = b'9P2000.u'

    def __init__(self, *args, **kwargs):
        '''
        Minimal setup.
        '''
        super().__init__(*args, **kwargs)
        return None
    async def process_msg(self, msgtype: int, msgbody: bytes) -> MsgT: # pylint: disable=too-many-branches
        '''
        The central dispatch method.
        '''
        if self.fallback_to_9P2000 or msgtype not in MODIFIED_MESSAGE_TYPES:
            return await super().process_msg(msgtype, msgbody)
        self._logger.debug(
            'Processing: %s %s %s'
            , msgtype, c.TRNAME.get(msgtype), msgbody.hex()
            )
        if msgtype == c.TVERSION:
            res = await p9_version(self.version_u, msgbody)
        elif msgtype == c.TAUTH:
            res = await p9u_auth(self.auth_u, msgbody)
        elif msgtype == c.TATTACH:
            res = await p9u_attach(self.attach_u, msgbody)
        elif msgtype == c.TSTAT:
            res = await p9u_stat(self.stat_u, msgbody)
        elif msgtype == c.TCREATE:
            res = await p9u_create(self.create_u, msgbody)
        elif msgtype == c.TWSTAT:
            res = await p9u_wstat(self.wstat_u, msgbody)
        else:
            raise NotImplementedError(msgtype, c.TRNAME.get(msgtype))
        self._logger.debug('Replying with message: %s %s', c.TRNAME.get(res[0]), res)
        return res
    def errhandler(self, exception):
        '''
        Attempts to provide sensible errnos.
        '''
        if isinstance(exception, Py9P2000u_Exception):
            errno = exception.errno
            msg = b''.join(
                arg if isinstance(arg, bytes) else str(arg).encode(c.ENCODING)
                for arg in exception.args[1:]
                )
        else:
            errno = 0xFF
            msg = str(exception).encode(c.ENCODING)
        return p9u_error(msg, errno)
    async def version_u(self, clientmax: int, clientver: bytes):
        '''
        A default version implementation that properly sets self.maxsize and
        manages fallback to 9P2000 if configured.
        '''
        self.maxsize = min(clientmax, self.maxsize)
        if clientver == self._versionstring:
            self._logger.debug('Client and server version agree: %s', clientver)
            srvver = clientver
        elif self.offer_fallback_to_9P2000 and clientver == b'9P2000':
            self._logger.debug('Falling back to %s from %s', clientver, srvver)
            srvver = clientver
            self.fallback_to_9P2000 = True
        return self.maxsize, srvver
    async def auth_u(self, afid: bytes, uname: bytes, aname: bytes, n_uname: int) -> bytes:
        '''
        Abstract auth method.
        '''
        raise NotImplementedError
    async def attach_u( # pylint: disable=too-many-arguments
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
    async def stat_u(self, fid: bytes) -> Py9P2000uStat:
        '''
        Abstract stat method.
        '''
        raise NotImplementedError
    async def create_u( # pylint: disable=too-many-arguments
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
    async def wstat_u(self, fid: bytes, stat: Py9P2000uStat) -> None:
        '''
        Abstract wstat method.
        '''
        raise NotImplementedError

def p9u_error(data: bytes, errno: int) -> MsgT:
    '''
    Format data as an error reply.
    '''
    msglen, msgfields = mkbytefields(data)
    return c.RERROR, msglen + 4, msgfields + (mkfield(errno, 4),)

async def p9u_attach(
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

async def p9u_auth(
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

async def p9u_stat(
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

async def p9u_create(
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

async def p9u_wstat(
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
