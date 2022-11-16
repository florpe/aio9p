# pylint: disable=duplicate-code
'''
A simple 9P2000.u implementation.
'''

from os import strerror

from aio9p.constant import DMDIR, DMFILE, RERROR
from aio9p.dialect import Py9P2000u
from aio9p.helper import mkstrfields, mkqid, mkfield
from aio9p.protocol import Py9PException, Py9PBadFID
from aio9p.stat import Py9P2000uStat

from aio9p.example.simple import Simple9P2000, BASEQID

from aio9p.example import example_main

class Simple9P2000u(Simple9P2000, Py9P2000u):
    '''
    The actual implementation.
    '''
    def __init__(self, maxsize, *_, logger=None, **__):
        '''
        Setup that populates the instance with a default base directory
        and file.
        '''
        super().__init__(maxsize, logger=logger)
        self.offer_fallback_to_9P2000 = True # pylint: disable=invalid-name
        self._fid = {}
        self._stat = {}
        self._content = {}
        self._direntry = {}
        return None
    def errhandler(self, exception):
        '''
        If the error is Py9P-specific, attempt to provide a proper
        error reply.
        '''
        self._logger.debug('Handling exception: %s', exception)
        msg = exception.args[0] if len(exception.args) > 0 else None
        self._logger.debug('Exception message: %s', msg)
        if isinstance(exception, Py9PException):
            if isinstance(msg, int):
                self._logger.debug('Py9PException %s, integer %s', exception, msg)
                errstr = strerror(msg)
                errno = msg
            else:
                self._logger.debug('Py9PException %s, message: %s', exception, msg)
                errstr = str(msg)
                errno = 0
        else:
            self._logger.debug('Non-Py9PException: %s', msg)
            errstr = f'Exception: {exception}'
            errno = 0
        errstrlen, errstrfields = mkstrfields(errstr)
        errnofield = mkfield(errno, 4)
        self._logger.debug('Error message formatting: %s %s', errstrfields, errstrlen)
        return errstrlen + 4, RERROR, (*errstrfields, errnofield)
    async def attach_u(self, fid, afid, uname, aname, n_uname): # pylint: disable=too-many-arguments
        '''
        Implementation.
        '''
        self._fid[fid] = BASEQID
        self._direntry[BASEQID] = {}
        self._stat[BASEQID] = Py9P2000uStat(
            p9type=0
            , p9dev=0
            , p9qid=BASEQID
            , p9mode=(DMDIR | 0o777)
            , p9atime=0
            , p9mtime=0
            , p9length=0
            , p9name=b'/'
            , p9uid=b'root'
            , p9gid=b'root'
            , p9muid=b'root'
            , p9u_extension=b''
            , p9u_n_uid=0
            , p9u_n_gid=0
            , p9u_n_muid=0
            )
        return BASEQID
    async def auth_u(self, afid, uname, aname, n_uname):
        '''
        No authentication.
        '''
        self._logger.error('Attempted auth: %s %s %s %s', afid, uname, aname, n_uname)
        raise NotImplementedError
    async def stat_u(self, fid):
        '''
        Returns a standard stat object.
        '''
        qid = self._fid.get(fid)
        stat = self._stat.get(qid)
        if stat is None:
            self._logger.error(
                'Bad Stat FID: %s %s %s %s %s'
                , fid, qid, stat, self._fid, self._stat
                )
            raise Py9PBadFID
        self._logger.debug('Returning stat: %s', stat)
        return stat
    async def create_u(self, fid, name, perm, mode, extension): # pylint: disable=too-many-arguments
        '''
        Implementation. New qids are created by picking the
        greatest unused one.
        '''
        qid = self._fid.get(fid)
        dircontent = self._direntry.get(qid)
        dirstat = self._stat.get(qid)
        if dircontent is None or dirstat is None:
            self._logger.error('Bad Create FID: %s %s', fid, self._fid, self._stat)
            raise Py9PBadFID
        if name in dircontent.keys():
            self._logger.error('Bad Create filename: %s %s %s', name, qid, dircontent)
            raise Py9PException(f'File name exists: {name}')
        newqid = mkqid(
            mode
            , int.from_bytes(max(k[5:] for k in self._stat), 'little') + 1
            )
        dircontent[name] = newqid
        parentmode = dirstat.p9mode
        if perm & DMDIR:
            mode = DMDIR | ( perm & (~0o666 | (parentmode  & 0o666) ) )
            self._direntry[newqid] = {}
        else:
            mode = DMFILE | ( perm & (~0o777 | (parentmode  & 0o777) ) )
            self._content[newqid] = b''
        self._stat[newqid] = Py9P2000uStat(
            p9type=0
            , p9dev=0
            , p9qid=newqid
            , p9mode=mode
            , p9atime=0
            , p9mtime=0
            , p9length=0
            , p9name=name
            , p9uid=b'root'
            , p9gid=b'root'
            , p9muid=b'root'
            , p9u_extension=extension
            , p9u_n_uid=0
            , p9u_n_gid=0
            , p9u_n_muid=0
            )
        self._fid[fid] = newqid
        return await self.open(fid, mode)
    async def wstat_u(self, fid, stat):
        '''
        Implementation.
        '''
        qid = self._fid.get(fid)
        estat = self._stat.get(qid)
        if estat is None:
            self._logger.error('Bad WStat FID: %s %s', fid, self._fid)
            raise Py9PBadFID
        self._logger.debug('WStat: %s %s', estat, stat)
        try:
            nstat = estat.wstat(stat)
        except ValueError as e:
            self._logger.debug('WStat update error: %s', e)
            raise Py9PException('Bad stat update') from e
        self._stat[qid] = nstat
        return None

if __name__ == "__main__":
    example_main(Simple9P2000u)
