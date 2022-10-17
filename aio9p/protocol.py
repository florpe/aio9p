
from asyncio import create_task, Protocol

import aio9p.constant as c
from aio9p.helper import extract, extract_bytefields, mkfield, mkbytefield, mkstrfield
from aio9p.stat import Py9PStat

class Py9PException(Exception):
    pass

Py9PBadFID = Py9PException('Bad fid!')

class Py9PProtocol(Protocol):
    def __init__(self, implementation):
        print('Built protocol!')
        self.maxsize = 256 #Default, overwritten by version negotiation
        self.implementation = implementation
        
        self._tasks = {}

        self._transport = None
        self._buffer = b''
        self._writeoffset = 0
        self._msglen = 0

        return None
    def connection_made(self, transport):
        print('Connection made')
        self._transport = transport
        return None
    def connection_lost(self, exc):
        print('Lost connection:', exc)
        return None
    def eof_received(self):
        print('End of file received')
        return None
    def data_received(self, data):
        print('Data received:', data)
        buffer = self._buffer + data
        buflen = len(buffer)
        tasks = self._tasks
        msgstart = 0
        while msgstart < buflen - 7:
            msgsize = extract(buffer, msgstart, 4)
            msgend = msgstart + msgsize
            if buflen < msgend:
                break

            msgtype = extract(buffer, msgstart+4, 1)
            msgtag = buffer[msgstart+5:msgstart+7]

            if msgtype == c.TFLUSH:
                self.flush(msgtag, buffer[msgstart+7:msgstart+9])
                msgstart = msgend
                continue
            task = create_task(
                self.implementation.process_msg(msgtype, buffer[msgstart+7:msgend])
            )
            tasks[msgtag] = task
            task.add_done_callback(lambda x: self.sendmsg(msgtag, x))
            #Check if Flush
            #Create task - or: Chop out size, msgt, tag, and queue
            msgstart = msgend
        self._buffer = buffer[msgstart:]
        return None
    def flush(self, tag, oldtag):
        task = self._tasks.pop(oldtag, None)
        if task is None or task.cancelled():
            pass
        else:
            task.cancel()
        self._transport.writelines((
            mkfield(7, 7)
            , mkfield(c.RFLUSH, 1)
            , tag
            ))
        return None
    def sendmsg(self, msgtag, task):
        if task.cancelled():
            print('Task cancelled:', msgtag)
            return None
        task_stored = self._tasks.pop(msgtag, None)
        if not task_stored == task:
            print('Mismatched task', msgtag)
            raise ValueError(msgtag, task, task_stored)
        exception = task.exception()
        if exception is None:
            reslen, restype, fields = task.result()
        else:
            print('Sendmsg: Got exception', msgtag, exception, task)
            reslen, restype, fields = self.implementation.errhandler(exception)
        res = (
            mkfield(reslen + 7, 4)
            , mkfield(restype, 1)
            , msgtag
            ) + fields
        binres = b''.join(res)
        print('Sendmsg: Sending', binres.hex())
        self._transport.write(binres)
        return None


class Py9P2000():
    versionstring = b'9P2000'
    def __init__(self, maxsize, *args, **kwargs):
        print('Build parser')
        self.maxsize = maxsize
        return None
    def errhandler(self, exception):
        errstr = str(exception).encode(c.ENCODING)[:self.maxsize-9]
        print('Got exception:', errstr, exception)
        return c.RERROR, 2 + len(errstr), (mkfield(len(errstr), 2), errstr)
    async def process_msg(self, msgtype, msgbody):
        print(f'\nProcessing: {msgtype} {c.TRNAME.get(msgtype)} {msgbody.hex()}')
        if msgtype == c.TVERSION:
            return await self.fmt_version(msgbody)
        if msgtype == c.TATTACH:
            return await self.fmt_attach(msgbody)
        if msgtype == c.TSTAT:
            return await self.fmt_stat(msgbody)
        if msgtype == c.TCLUNK:
            return await self.fmt_clunk(msgbody)
        if msgtype == c.TWALK:
            return await self.fmt_walk(msgbody)
        if msgtype == c.TOPEN:
            return await self.fmt_open(msgbody)
        if msgtype == c.TREAD:
            return await self.fmt_read(msgbody)
        if msgtype == c.TWRITE:
            return await self.fmt_write(msgbody)
        if msgtype == c.TCREATE:
            return await self.fmt_create(msgbody)
        if msgtype == c.TWSTAT:
            return await self.fmt_wstat(msgbody)
        if msgtype == c.TREMOVE:
            return await self.fmt_remove(msgbody)
        print('Unknown message type', msgtype)
        raise NotImplementedError


    async def fmt_version(self, msgbody):
        #TODO: Abort outstanding IO
        maxsize = extract(msgbody, 0, 4)
        versionlength = extract(msgbody, 4, 2)
        if len(msgbody) < 6 + versionlength:
            print('Message body too short for version string')
            raise ValueError(msgbody)
        version = msgbody[6:6+versionlength]
        srvmax, srvver = await self.version(maxsize, version)
        self.maxsize = min(maxsize, srvmax)
        srvverlen = len(srvver)
        return 6 + srvverlen, c.RVERSION, (
            srvmax.to_bytes(4, 'little')
            , srvverlen.to_bytes(2, 'little')
            , srvver
            )
    async def version(self, client_maxsize, client_version):
        return client_maxsize, self.versionstring

    async def fmt_attach(self, msgbody):
        fid = msgbody[0:4]
        afid = msgbody[4:8]
        unamelen = extract(msgbody, 8, 2)
        uname = msgbody[10:10+unamelen]

        anamelen = extract(msgbody, 10+unamelen, 2)
        aname = msgbody[10+unamelen:12+anamelen]

        qid = await self.attach(fid, afid, uname, aname)

        return 13, c.RATTACH, (qid,)
    async def attach(self, fid, afid, uname, aname):
        raise NotImplementedError

    async def fmt_auth(self, msgbody):
        afid = msgbody[0:4]
        unamelen = extract(msgbody, 4, 2)
        uname = msgbody[6:6+unamelen]

        anamelen = extract(msgbody, 6+unamelen, 2)
        aname = msgbody[8+unamelen:8+unamelen+anamelen]

        aqid = await self.auth(afid, uname, aname)

        return 13, c.RAUTH, (aqid,)
    async def auth(self, afid, uname, aname):
        raise NotImplementedError

    async def fmt_stat(self, msgbody):
        fid = msgbody[0:4]
        statres = await self.stat(fid)
        statbytes = statres.to_bytes(with_envelope=True)
        print('@ Stat:', statbytes.hex())
        for k, v in statres.to_dict().items():
            print('@', k, v)
        return len(statbytes), c.RSTAT, (statbytes,)
    async def stat(self, fid):
        raise NotImplementedError

    async def fmt_clunk(self, msgbody):
        fid = msgbody[0:4]
        await self.clunk(fid)
        print('Clunked!')
        return 0, c.RCLUNK, ()
    async def clunk(self, fid):
        raise NotImplementedError

    async def fmt_walk(self, msgbody):
        print('Walking!', msgbody.hex())
        fid = msgbody[0:4]
        newfid = msgbody[4:8]
        count = extract(msgbody, 8, 2)
        try:
            wnames = extract_bytefields(msgbody, 10, count)
        except AssertionError as e:
            print(f'Could not build walknames: {count=} {msgbody[10:].hex()=}')
            raise
        qids = await self.walk(fid, newfid, wnames)
        if count and not qids:
            errmsg = b'No such file!'
            errenvelope = mkfield(13, 2)
            return 15, c.RERROR, (errenvelope, errmsg)
        qidcount = len(qids)
        return 2 + 13*qidcount, c.RWALK, (mkfield(qidcount, 2),) + qids
    async def walk(self, fid, newfid, wnames):
        raise NotImplementedError

    async def fmt_open(self, msgbody):
        fid = msgbody[0:4]
        mode = extract(msgbody, 4, 1)
        qid, iounit = await self.open(fid, mode)
        return 17, c.ROPEN, (qid, mkfield(iounit, 4))
    async def open(self, fid, mode):
        raise NotImplementedError

    async def fmt_read(self, msgbody):
        fid = msgbody[0:4]
        offset = extract(msgbody, 4, 8)
        count = extract(msgbody, 12, 4)
        resdata = await self.read(fid, offset, count)
        #TODO: Length overflow checking
        resdatalen = len(resdata)
        return 4 + resdatalen, c.RREAD, (mkfield(resdatalen, 4), resdata)
    async def read(self, fid, offset, count):
        raise NotImplementedError

    async def fmt_write(self, msgbody):
        fid = msgbody[0:4]
        offset = extract(msgbody, 4, 8)
        count = extract(msgbody, 12, 4)
        #TODO: Check that count matches the size
        data = msgbody[16:16+count]
        rescount = await self.write(fid, offset, data)
        return 4, c.RWRITE, (mkfield(rescount, 4),)
    async def write(self, fid, offset, data):
        raise NotImplementedError

    async def fmt_create(self, msgbody):
        fid = msgbody[0:4]
        namelen = extract(msgbody, 4, 2)
        name = msgbody[6:6+namelen]

        perm = extract(msgbody, 6+namelen, 4)
        mode = extract(msgbody, 10+namelen, 1)
        qid, iounit = await self.create(fid, name, perm, mode)
        print(f'@@@@ {qid=} {iounit=}')
        return 17, c.RCREATE, (qid, mkfield(iounit, 4))
    async def create(self, fid, name, perm, mode):
        raise NotImplementedError

    async def fmt_wstat(self, msgbody):
        fid = msgbody[0:4]
        stat = Py9PStat.from_bytes(msgbody, 6)
        await self.wstat(fid, stat)
        return 0, c.RWSTAT, ()
    async def wstat(self, fid, stat):
        raise NotImplementedError

    async def fmt_remove(self, msgbody):
        fid = msgbody[0:4]
        await self.remove(fid)
        return 0, c.RREMOVE, ()
        raise NotImplementedError
    async def remove(self, fid):
        raise NotImplementedError
