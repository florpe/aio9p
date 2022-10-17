
class Implementation9P():
    def errhandler(self, exception):
        # Returns reslen, restype, (field, field, ...)
        raise NotImplementedError

    async def version(self, maxsize, version):
        # Returns maxsize, version
        raise NotImplementedError
    async def attach(self, fid, afid, uname, aname, *args):
        # 9P2000.u : args = (n_uname,)
        # Returns root qid
        raise NotImplementedError
    async def auth(self, afid, uname, aname, *args):
        # 9P2000.u : args = (n_uname,)
        raise NotImplementedError
    async def walk(self, fid, newfid, wnames):
        raise NotImplementedError
    async def read(self, fid, offset, count):
        raise NotImplementedError
    async def write(self, fid, offset, count, data):
        raise NotImplementedError
    async def clunk(self, fid):
        raise NotImplementedError
    async def remove(self, fid):
        raise NotImplementedError


    #9P2000.L
    async def statfs(self, fid):
        raise NotImplementedError
    async def lopen(self, fid, openflags):
        raise NotImplementedError
    async def lcreate(self, fid, name, createflags, mode, gid):
        raise NotImplementedError
    async def symlink(self, fid, name, symtgt, gid):
        raise NotImplementedError
    async def mknod(self, dfid, name, mode, major, minor, gid):
        raise NotImplementedError
    async def readlink(self, fid):
        raise NotImplementedError
    async def getattr(self, fid, reqmask):
        raise NotImplementedError
    async def setattr(self, fid, valid, mode, uid, gid, size, atime_sec, atime_nsec, mtime_sec, mtime_nsec):
        raise NotImplementedError
    async def xattrwalk(self, fid, newfid, name):
        raise NotImplementedError
    async def xattrcreate(self, fid, attr_size, flags):
        #Attention: The actual setxattr should happen when fid is clunked
        raise NotImplementedError
    async def readdir(self, fid, offset, count):
        raise NotImplementedError
    async def fsync(self, fid):
        raise NotImplementedError
    async def lock(self, fid, locktype, flags, start, length, proc_id, client_id):
        raise NotImplementedError
    async def getlock(self, fid, locktype, start, length, proc_id, client_id):
        raise NotImplementedError
    async def link(self, dfid, fid, name):
        raise NotImplementedError
    async def mkdir(self, dfid, name, mode, gid):
        raise NotImplementedError
    async def renameat(self, olddirfid, oldname, newdirfd, newname):
        raise NotImplementedError
    async def unlinkat(self, dirfid, name, flags):
        raise NotImplementedError








