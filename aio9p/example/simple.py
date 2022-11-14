
'''
A simple 9P2000 implementation that stores file data in memory and ignores
any changes to file modes.
'''

from errno import ENOENT
from os import strerror

from aio9p.constant import QTByteDIR, DMDIR, DMFILE, RERROR, ENCODING
from aio9p.dialect import Py9P2000
from aio9p.helper import mkbytefields, mkstrfields, mkqid, mkfield
from aio9p.protocol import Py9PException, Py9PBadFID
from aio9p.stat import Py9P2000Stat

from aio9p.example import example_main

BASEQID = QTByteDIR + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x00'

class Simple9P2000(Py9P2000):
    '''
    The actual implementation.
    '''
    def __init__(self, maxsize, logger=None):
        '''
        Setup that populates the instance with a default base directory
        and file.
        '''
        super().__init__(maxsize, logger=logger)
        self._logger.info(
                'Simple9P running! Version: %s Class: %s'
            , self._versionstring
            , type(self).__name__
            )
        self._fid = {}
        self._stat = {}
        self._content = {}
        self._direntry = {}
        return None
    def errhandler(self, exception):
        '''
        If the error is Py9P-specific, attempt to provide a proper
        error reply.
        The reply format with errno is technically 9P2000.u-specific, but
        the Linux driver appears to need it.
        '''
        self._logger.debug('Exception: %s', exception)
        if isinstance(exception, Py9PException):
            msg = exception.args[0]
            self._logger.debug('Py9PException: %s', msg)
        else:
            msg = f'Exception: {exception}'
        if isinstance(msg, int):
            errstr = strerror(msg)
            self._logger.debug('Integer exception %i, message %s', msg, errstr)
            errstrlen, errstrfields = mkstrfields(errstr)
            errnofield = mkfield(msg, 4)
            return errstrlen + 4, RERROR, (*errstrfields, errnofield)
        bytemsg = str(msg).encode(ENCODING)
        msgfieldslen, msgfields = mkbytefields(bytemsg)
        return msgfieldslen, RERROR, msgfields
    async def attach(self, fid, __, ___, ____):
        '''
        Implementation.
        '''
        self._fid[fid] = BASEQID
        self._direntry[BASEQID] = {}
        self._stat[BASEQID] = Py9P2000Stat(
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
            )
        return BASEQID
    async def auth(self, afid, uname, aname):
        '''
        No auth necessary.
        '''
        self._logger.error('Attempted auth: %s %s %s', afid, uname, aname)
        raise NotImplementedError
    async def stat(self, fid):
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
    async def clunk(self, fid):
        '''
        Drops the fid.
        '''
        self._fid.pop(fid, None)
        return None
    async def walk(self, fid, newfid, wnames):
        '''
        Implementation.
        '''
        qids = []
        curr_qid = self._fid.get(fid)
        if curr_qid is None:
            self._logger.error('Bad Walk FID: %s %s', fid, self._fid)
            raise Py9PBadFID
        if not wnames:
            self._fid[newfid] = curr_qid
            self._logger.debug('Identity Walk: %s %s', fid, newfid)
            return ()
        dirs = self._direntry
        for wname in wnames:
            dircontent = dirs.get(curr_qid, {})
            next_qid = dircontent.get(wname)
            self._logger.debug('Walking: %s %s %s', wname, next_qid, dircontent)
            if next_qid is None:
                break
            qids.append(next_qid)
            curr_qid = next_qid
        if not qids:
            self._logger.debug('Walk failed: %s %s', fid, wnames)
            raise Py9PException(ENOENT)
        if len(wnames) == len(qids):
            self._fid[newfid] = qids[-1]
        self._logger.debug('Walk result: %s %s %s', fid, wnames, qids)
        return tuple(qids)
    async def open(self, fid, mode):
        '''
        Does nothing.
        '''
        qid = self._fid.get(fid)
        if qid is None:
            raise Py9PBadFID
        return qid, 0
    async def read(self, fid, offset, count):
        '''
        Implementation.
        '''
        qid = self._fid.get(fid)
        if qid is None:
            self._logger.error('Bad Read FID: %s %s', fid, self._fid)
            raise Py9PBadFID
        filecontent = self._content.get(qid)
        if filecontent is not None:
            return filecontent[offset:offset+count]
        dircontent = self._direntry.get(qid)
        diroffset = 0
        res = []
        reslen = 0
        self._logger.debug('Reading directory: %s %s %s', offset, count, dircontent)
        for entryname, entryqid in sorted(dircontent.items()): #TODO: Check for bad offsets
            entrystat = self._stat.get(entryqid)
            if entrystat is None:
                raise Py9PBadFID
            entrysize = entrystat.size()
            self._logger.debug('Reading entry: %s %s %s', entryname, entrysize, entrystat)
            if offset <= diroffset and reslen + entrysize <= count:
                res.append(entrystat)
                reslen = reslen + entrysize
            else:
                break
            diroffset = diroffset + entrysize
        return b''.join((entrystat.to_bytes() for entrystat in res))
    async def write(self, fid, offset, data):
        '''
        Implementation.
        '''
        qid = self._fid.get(fid)
        content = self._content.get(qid)
        stat = self._stat.get(qid)
        if content is None or stat is None:
            self._logger.error('Bad Write FID: %s %s', fid, self._fid, self._stat)
            raise Py9PBadFID
        self._logger.debug('Writing to %s at %i for length %i : %s ', qid, offset, len(data), data)
        if len(content) < offset:
            return 0
        newcontent = content[:offset] + data + content[offset+len(data):]
        self._content[qid] = newcontent
        stat.p9length = len(newcontent)
        return len(data)
    async def create(self, fid, name, perm, mode):
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
        self._stat[newqid] = Py9P2000Stat(
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
            )
        self._fid[fid] = newqid
        return await self.open(fid, mode)
    async def wstat(self, fid, stat):
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
    async def remove(self, fid):
        '''
        Implemention.
        '''
        qid = self._fid.pop(fid, None)
        if qid is None:
            return None
        filestat = self._stat.pop(qid, None)
        if filestat is None:
            return None
        filename = filestat.p9name
        for dirc in self._direntry.values():
            if dirc.get(filename) == qid:
                dirc.pop(filename)
        self._direntry.pop(qid, None)
        self._content.pop(qid, None)
        return None

if __name__ == "__main__":
    example_main(Simple9P2000)
