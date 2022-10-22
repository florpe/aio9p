
from errno import ENOENT
from os import strerror

from aio9p.constant import QTByteDIR, DMDIR, QTByteFILE, DMFILE, RERROR, ENCODING
from aio9p.helper import mkbytefield, mkstrfield, mkqid, mkfield
from aio9p.protocol import Py9PException, Py9P2000, Py9PException, Py9PBadFID
from aio9p.stat import Py9PStat

from aio9p.example import example_main

BASEQID = QTByteDIR + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x00'
FILEQID = QTByteFILE + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x00'

BASENAME = b'/'
FILENAME = b'barfile'
FILECONTENT = b'Hello, barfilereader'

BASESTAT = Py9PStat(
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

def filestat(fc):
    return Py9PStat(
        p9type=0
        , p9dev=0
        , p9qid=FILEQID
        , p9mode=(DMFILE | 0o777)
        , p9atime=0
        , p9mtime=0
        , p9length=len(fc)
        , p9name=FILENAME
        , p9uid=b'root'
        , p9gid=b'root'
        , p9muid=b'root'
        )

def mkfilestat(qid, qname, qlen):
    return Py9PStat(
        p9type=0
        , p9dev=0
        , p9qid=qid
        , p9mode=(DMFILE | 0o777)
        , p9atime=0
        , p9mtime=0
        , p9length=qlen
        , p9name=qname
        , p9uid=b'root'
        , p9gid=b'root'
        , p9muid=b'root'
        )

def mkdirstat(qid, qname):
    return Py9PStat(
        p9type=0
        , p9dev=0
        , p9qid=qid
        , p9mode=(DMDIR | 0o777)
        , p9atime=0
        , p9mtime=0
        , p9length=0
        , p9name=qname
        , p9uid=b'root'
        , p9gid=b'root'
        , p9muid=b'root'
        )

def mkstatlen(name):
    return 49 + len(name) + 4 + 4 + 4

class Simple9P(Py9P2000):
    def __init__(self, maxsize, logger=None):
        super().__init__(maxsize, logger=logger)
        self._logger.info('Simple9P running! Version:', self.version)
        self._fid = {}
        self._name = {
            BASEQID: BASENAME
            , FILEQID: FILENAME
            }
        self._dircontent = {
            BASEQID: {
                FILENAME: FILEQID
                }
            }
        self._content = {
            FILEQID: FILECONTENT
            }
        return None
    def errhandler(self, exception):
        self._logger.debug('Exception: %s', exception)
        if isinstance(exception, Py9PException):
            msg = exception.args[0]
            self._logger.debug('Py9PException:', msg)
        else:
            msg = f'Exception: {exception}'
        if isinstance(msg, int):
            errstr = strerror(msg)
            self._logger.debug(f'Integer exception %i, message %s', msg, errstr)
            errstrlen, errstrfields = mkstrfield(errstr)
            errnofield = mkfield(msg, 4)
            return errstrlen + 4, RERROR, (*errstrfields, errnofield)
        bytemsg = str(msg).encode(ENCODING)
        msgfieldslen, msgfields = mkbytefield(bytemsg)
        return msgfieldslen, RERROR, msgfields
    async def maxsize_backend(self, client_maxsize):
        return 65535
    async def attach(self, fid, afid, uname, aname):
        self._fid[fid] = BASEQID
        return BASEQID
    async def auth(self, afid, uname, aname):
        self._logger.error('Attempted auth: %s %s %s', afid, uname, aname)
        raise NotImplementedError
    async def stat(self, fid):
        qid = self._fid.get(fid)
        name = self._name.get(qid)
        if name is None:
            raise Py9PBadFID
        content = self._content.get(qid)
        if content is not None:
            return mkfilestat(qid, name, len(content))
        return mkdirstat(qid, name)
    async def clunk(self, fid):
        self._fid.pop(fid, None)
        return None
        
    async def walk(self, fid, newfid, wnames):
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
        # if mode in {1, 2}:
        #     raise Py9PException('Files are read-only')
        qid = self._fid.get(fid)
        if qid is None:
            raise Py9PBadFID
        return qid, 0
    async def read(self, fid, offset, count):
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
            if diroffset == offset:
                entrycontent = self._content.get(entryqid)
                if entrycontent is None:
                    return mkdirstat(entryqid, entryname).to_bytes()
                return mkfilestat(entryqid, entryname, len(entrycontent)).to_bytes()
            if diroffset > offset:
                raise Py9PException('Bad directory read offset')
            diroffset = diroffset + mkstatlen(entryname)
        return b''
    async def write(self, fid, offset, data):
        #TODO: Check that fid is okay
        qid = self._fid.get(fid)
        fc = self._content.get(qid)
        if fc is None: #TODO: Writes to directories should give different error
            self._logger.error('Bad Write FID: %s %s', fid, self._fid)
            raise Py9PBadFID
        self._logger.debug('Writing to %s at %i for length %i : %s ', qid, offset, len(data), data)
        if len(fc) < offset:
            return 0
        self._content[qid] = fc[:offset] + data + fc[offset+len(data):]
        return len(data)
    async def create(self, fid, name, perm, mode):
        qid = self._fid.get(fid)
        dircontent = self._dircontent.get(qid)
        if dircontent is None:
            self._logger.error('Bad Create FID: %s %s', fid, self._fid)
            raise Py9PBadFID
        if name in dircontent.keys():
            self._logger.error('Bad Create filename: %s %s %s', name, qid, dircontent)
            raise Py9PException(f'File name exists: {name}')
        newqid = mkqid(
            mode
            , int.from_bytes(max(k[5:] for k in self._name.keys()), 'little') + 1
            )
        dircontent[name] = newqid
        self._name[newqid] = name
        if perm & DMDIR:
            self._dircontent[newqid] = {}
        else:
            self._content[newqid] = b''
        self._fid[fid] = newqid
        return newqid, 0
    async def wstat(self, fid, stat):
        return None
    async def remove(self, fid):
        qid = self._fid.pop(fid, None)
        if qid is None:
            return None
        filename = self._name.pop(qid, None)
        for dirc in self._dircontent.values():
            if dirc.get(filename) == qid:
                dirc.pop(filename)
        self._dircontent.pop(qid, None)
        self._content.pop(qid, None)
        return None


if __name__ == "__main__":
    example_main(Simple9P)

