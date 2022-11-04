
'''
A simple 9P2000 implementation that stores file data in memory and ignores
any changes to file modes.
'''

from errno import ENOENT
from os import strerror

from aio9p.constant import QTByteDIR, DMDIR, QTByteFILE, DMFILE, RERROR, ENCODING
from aio9p.helper import mkbytefields, mkstrfields, mkqid, mkfield
from aio9p.protocol import Py9PException, Py9PBadFID
from aio9p.dialect import Py9P2000
from aio9p.stat import Py9P2000Stat

from aio9p.example import example_main

BASEQID = QTByteDIR + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x00'
FILEQID = QTByteFILE + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x00'

BASENAME = b'/'
FILENAME = b'barfile'
FILECONTENT = b'Hello, barfilereader'

BASESTAT = Py9P2000Stat(
    p9type=0
    , p9dev=0
    , p9qid=BASEQID
    , p9mode=(DMDIR | 0o777)
    , p9atime=0
    , p9mtime=0
    , p9length=0
    , p9name=BASENAME
    , p9uid=b'root'
    , p9gid=b'root'
    , p9muid=b'root'
    )

'''
def filestat(filecontent):
    ''
    Create a stat object based on content length.
    ''
    return Py9P2000Stat(
        p9type=0
        , p9dev=0
        , p9qid=FILEQID
        , p9mode=(DMFILE | 0o777)
        , p9atime=0
        , p9mtime=0
        , p9length=len(filecontent)
        , p9name=FILENAME
        , p9uid=b'root'
        , p9gid=b'root'
        , p9muid=b'root'
        )
'''
def mkfilestat(qid, qname, qlen, perm=0o777, parentmode=0o777):
    '''
    Create a stat object for a regular file.
    '''
    mode = perm & (~0o666 | (parentmode  & 0o666) )
    return Py9P2000Stat(
        p9type=0
        , p9dev=0
        , p9qid=qid
        , p9mode=(DMFILE | mode)
        , p9atime=0
        , p9mtime=0
        , p9length=qlen
        , p9name=qname
        , p9uid=b'root'
        , p9gid=b'root'
        , p9muid=b'root'
        )

def mkdirstat(qid, qname, perm=0o777, parentmode=0o777):
    '''
    Create a stat object for a directory.
    '''
    mode = perm & (~0o777 | (parentmode  & 0o777) )
    return Py9P2000Stat(
        p9type=0
        , p9dev=0
        , p9qid=qid
        , p9mode=(DMDIR | mode)
        , p9atime=0
        , p9mtime=0
        , p9length=0
        , p9name=qname
        , p9uid=b'root'
        , p9gid=b'root'
        , p9muid=b'root'
        )

def mkstatlen(name):
    '''
    Given a file or directory name, culate the length of the corresponding
    stat object.
    '''
    return 49 + len(name) + 4 + 4 + 4

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
        self._logger.info('Simple9P2000 running! Version: %s', self.version)
        self._fid = {}
        self._dircontent = {
            BASEQID: {
                FILENAME: FILEQID
                }
            }
        self._content = {
            FILEQID: FILECONTENT
            }
        self._stat = {
            FILEQID: mkfilestat(FILEQID, FILENAME, len(FILECONTENT))
            , BASEQID: mkdirstat(BASEQID, BASENAME)
            }
        return None
    def errhandler(self, exception):
        '''
        If the error is Py9P-specific, attempt to provide a proper
        error reply.
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
    async def attach(self, fid, afid, uname, aname):
        '''
        Implementation.
        '''
        self._fid[fid] = BASEQID
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
        self._logger.debug('Simple walk from %s to %s: %s', fid, newfid, wnames)
        if not wnames:
            oldqid = self._fid.get(fid)
            if oldqid is None:
                raise Py9PBadFID
            self._fid[newfid] = oldqid
            return ()
        dirqid = self._fid.get(fid)
        wqids = []
        for wname in wnames:
            dircontent = self._dircontent.get(dirqid, {})
            wqid = dircontent.get(wname)
            if wqid is None:
                break
            wqids.append(wqid)
            dirqid = wqid
        if not wqids:
            raise Py9PException(ENOENT)
        if len(wqids) == len(wnames):
            self._fid[newfid] = wqids[-1]
        return tuple(wqids)
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
        content = self._content.get(qid)
        if content is not None:
            return content[offset:offset+count]
        dircontent = self._dircontent.get(qid)
        if dircontent is None:
            raise Py9PBadFID
        diroffset = 0
        for entryname, entryqid in sorted(dircontent.items()):
            entrystat = self._stat.get(entryqid)
            if entrystat is None:
                raise Py9PException('Bad directory entry', qid, entryname, entryqid)
            if diroffset == offset:
                self._logger.debug('About to return entry: %s %s', entryname, entrystat)
                entrybytes = entrystat.to_bytes()
                self._logger.debug('Returning entry: %s %s', entryname, entrybytes.hex())
                return entrystat.to_bytes()
            if diroffset > offset:
                raise Py9PException('Bad directory read offset')
            diroffset = diroffset + entrystat.size()
        return b''
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
        dircontent = self._dircontent.get(qid)
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

        if perm & DMDIR:
            self._dircontent[newqid] = {}
            self._stat[qid] = mkdirstat(
                newqid
                , name
                , perm=perm
                , parentmode=dirstat.mode
                )
        else:
            self._content[newqid] = b''
            self._stat[qid] = mkfilestat(
                newqid
                , name
                , 0
                , perm=perm
                , parentmode=dirstat.mode
                )
        self._fid[fid] = newqid
        return await self.open(fid, mode)
    async def wstat(self, fid, stat):
        '''
        Update permissions, file size, etc.
        '''
        qid = self._fid.get(fid)
        estat = self._stat.get(qid)
        if estat is None:
            self._logger.error('Bad WStat FID: %s %s', fid, self._fid)
            raise Py9PBadFID

        self._logger.debug('WStat: %s %s', estat, stat)
        
        if stat.p9mode != 0xffffffff:
            estat.setmode(stat.p9mode)

        elen = estat.p9length
        nlen = stat.p9length
        if nlen == 0xffffffff:
            self._logger.debug('Not setting length, nlen at maximum')
            pass
        elif elen < nlen:
            content = self._content.get(qid)
            if not content:
                raise Py9PException('Cannot set directory length')
            self._logger.debug('Not elongating file to %s', nlen)
            # self._content[qid] = content + bytes(nlen - elen)
            # estat.p9length = elen
        elif nlen < elen:
            self._logger.debug('Truncating file to %s', nlen)
            content = self._content.get(qid)
            if not content:
                raise Py9PException('Cannot set directory length')
            self._content[qid] = content[:nlen]
            estat.p9length = elen
        else:
            self._logger.debug('Not setting length, unchanged')
        if stat.p9mtime != 0xffffffff:
            self._logger.debug('Setting mtime: %s', stat.p9mtime)
            estat.p9mtime = stat.p9mtime
            self._logger.debug('Set mtime: %s', stat.p9mtime)
        if stat.p9atime != 0xffffffff:
            estat.p9atime = stat.p9atime
            self._logger.debug('Setting atime: %s', stat.p9atime)
            estat.p9atime = stat.p9atime
            self._logger.debug('Set atime: %s', stat.p9atime)
        if stat.p9uid:
            estat.p9uid = stat.p9uid
        if stat.p9gid:
            estat.p9gid = stat.p9gid
        if stat.p9muid:
            estat.p9muid = stat.p9muid
        nname = stat.p9name
        ename = estat.p9name
        if nname and ename != nname:
            estat.p9name = nname
            for dirc in self._dircontent.values():
                if dirc.get(ename) != qid:
                    continue
                if nname in dirc:
                    raise Py9PException('File exists')
                dirc[nname] = qid
                dirc.pop(ename, None)
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
        for dirc in self._dircontent.values():
            if dirc.get(filename) == qid:
                dirc.pop(filename)
        self._dircontent.pop(qid, None)
        self._content.pop(qid, None)
        return None

if __name__ == "__main__":
    example_main(Simple9P2000)
