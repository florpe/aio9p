# pylint: disable=invalid-name
'''
A 9P2000u client implementation. The individual parser-formatters
are provided as functions instead of methods to enable reuse by
other versions of the protocol.
'''

from typing import Tuple

import aio9p.constant as c
from aio9p.dialect.client.Py9P2000 import Py9P2000Client, p9_wstat
from aio9p.helper import (
    extract
    , mkbytefields
    , mkfield
    )
from aio9p.stat import Py9P2000uStat

async def p9u_attach( # pylint: disable=too-many-arguments
    implementation
    , fid: bytes
    , afid: bytes
    , uname: bytes
    , aname: bytes
    , n_uname: int
    ) -> bytes:
    '''
    Create a TATTACH message.
    Parse an RATTACH message.
    '''
    varfieldslen, varfields = mkbytefields(uname, aname)
    fields = (
        fid
        , afid
        , *varfields
        , mkfield(n_uname, 4)
        )
    _, msgbody = await implementation.message(
        (c.TATTACH, 12+varfieldslen, fields)
        )
    return msgbody[:13]

async def p9u_auth(
    implementation
    , afid: bytes
    , uname: bytes
    , aname: bytes
    , n_uname: int
    ) -> bytes:
    '''
    Create a TAUTH message body.
    Parse an RAUTH message body.
    '''
    varfieldslen, varfields = mkbytefields(uname, aname)
    fields = (
        afid
        , *varfields
        , mkfield(n_uname, 4)
        )
    _, msgbody = await implementation.message(
        (c.TATTACH, 8+varfieldslen, fields)
        )
    return msgbody[:13]

async def p9u_stat(
    implementation
    , fid: bytes
    ) -> Py9P2000uStat:
    '''
    Create a TSTAT message body.
    Parse an RSTAT message body.
    '''
    _, msgbody = await implementation.message(
        (c.TSTAT, 4, (fid,))
        )
    return Py9P2000uStat.from_bytes(msgbody, 2)

async def p9u_create( # pylint: disable=too-many-arguments
    implementation
    , fid: bytes
    , name: bytes
    , perm: int
    , mode: int
    , extension: bytes
    ) -> Tuple[bytes, int]:
    '''
    Create a TCREATE message body.
    Parse an RCREATE message body.
    '''
    namelen, namefields = mkbytefields(name)
    extlen, extfields = mkbytefields(extension)
    fields = (fid, *namefields, mkfield(perm, 4), mkfield(mode, 1), *extfields)
    _, msgbody = await implementation.message(
        (c.TWRITE, 10 + namelen + extlen, fields)
        )
    return msgbody[:13], extract(msgbody, 13, 4)

async def p9u_wstat(
    implementation
    , fid: bytes
    , stat: Py9P2000uStat
    ) -> None:
    '''
    Create a TWSTAT message.
    Parse an RWSTAT message.

    The difference between p9_wstat and p9u_wstat is
    in the type of the stat argument.
    '''
    return await p9_wstat(implementation, fid, stat)

class Py9P2000uClient(Py9P2000Client): # pylint: disable=too-few-public-methods
    '''
    A client for the 9P2000 dialect.
    '''
    versionstring = b'9P2000.u'
    attach_u = p9u_attach
    auth_u = p9u_auth
    stat_u = p9u_stat
    create_u = p9u_create
    wstat_u = p9u_wstat
