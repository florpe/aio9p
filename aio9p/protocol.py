
from asyncio import create_task, Protocol


import aio9p.constant as c
from aio9p.helper import extract, extract_bytefields, mkfield, mkbytefield, NULL_LOGGER
from aio9p.stat import Py9PStat

class Py9PException(Exception):
    pass

Py9PBadFID = Py9PException('Bad fid!')

class Py9PProtocol(Protocol):
    _logger = NULL_LOGGER
    def __init__(self, implementation, logger=None):
        if logger is not None:
            self._logger = logger
        self.maxsize = 256 #Default, overwritten by version negotiation
        self.implementation = implementation

        self._transport = None

        self._tasks = {}
        self._buffer = b''

        return None
    def connection_made(self, transport):
        self._logger.info('Connection made')
        self._transport = transport
        return None
    def connection_lost(self, exc):
        if exc is None:
            self._logger.info('Connection terminated')
        else:
            self._logger.info('Lost connection: %s', exc)
        return None
    def eof_received(self):
        self._logger.info('End of file received')
        return None
    def data_received(self, data):
        self._logger.debug('Data received: %s', data)
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
            self._logger.debug('Sending message: cancelled task %s', msgtag)
            return None
        task_stored = self._tasks.pop(msgtag, None)
        if not task_stored == task:
            self._logger.debug('Sending message: Mismatched task %s', msgtag)
            raise ValueError(msgtag, task, task_stored)
        exception = task.exception()
        if exception is None:
            reslen, restype, fields = task.result()
        else:
            self._logger.info('Sending message: Got exception %s %s %s', msgtag, exception, task)
            reslen, restype, fields = self.implementation.errhandler(exception)
        res = (
            mkfield(reslen + 7, 4)
            , mkfield(restype, 1)
            , msgtag
            ) + fields
        binres = b''.join(res)
        self._logger.debug('Sending message: %s', binres.hex())
        self._transport.write(binres)
        self._logger.debug('Sent')
        return None


class Py9P2000():
    version = b'9P2000'
    _logger = NULL_LOGGER
    def __init__(self, maxsize, *args, logger=None, **kwargs):
        if logger is not None:
            self._logger = logger
        self.maxsize = maxsize
        return None
    def errhandler(self, exception):
        errstr = str(exception).encode(c.ENCODING)[:self.maxsize-9]
        self._logger.debug('Got exception: %s %s', errstr, exception)
        return c.RERROR, 2 + len(errstr), (mkfield(len(errstr), 2), errstr)
    async def process_msg(self, msgtype, msgbody):
        self._logger.debug('Processing: %s %s %s', msgtype, c.TRNAME.get(msgtype), msgbody.hex())
        dispatcher = {
            c.TVERSION: self._fmt_version
            , c.TATTACH: self._fmt_attach
            , c.TSTAT: self._fmt_stat
            , c.TCLUNK: self._fmt_clunk
            , c.TWALK: self._fmt_walk
            , c.TOPEN: self._fmt_open
            , c.TREAD: self._fmt_read
            , c.TWRITE: self._fmt_write
            , c.TCREATE: self._fmt_create
            , c.TWSTAT: self._fmt_wstat
            , c.TREMOVE: self._fmt_remove
            }
        processor = dispatcher.get(msgtype)
        if processor is None:
            self._logger.debug('Unknown message type %s', msgtype)
            raise NotImplementedError
        res = await processor(msgbody)
        self._logger.debug('Replying with message: %s', res)
        return res


    async def _fmt_version(self, msgbody):
        #TODO: Abort outstanding IO
        maxsize = extract(msgbody, 0, 4)
        versionlength = extract(msgbody, 4, 2)
        if len(msgbody) < 6 + versionlength:
            self._logger.error('Message body too short for version string')
            raise ValueError(msgbody)
        version = msgbody[6:6+versionlength]
        if version != self.version: #TODO: Check behaviour here
            srvverlen, srvverfields = mkbytefield(b'unknown')
            return 4 + srvverlen, c.RVERSION, (mkfield(256, 4), *srvverfields)
        srvmax = await self.maxsize_backend(maxsize)
        self.maxsize = min(maxsize, srvmax)
        srvverlen, srvverfields = mkbytefield(self.version)
        return 4 + srvverlen, c.RVERSION, (
            srvmax.to_bytes(4, 'little')
            , *srvverfields
            )
    async def maxsize_backend(self, client_maxsize):
        '''
        Calculates the backend's maximum message size. The implementation will
        transmit the minimum of client and backend size.

        The default here calculates the smallest power of two less than the
        client maximum. It can and probably should be overridden.
        '''
        res = 1024
        while res < client_maxsize:
            res = res << 1
        return res >> 1

    async def _fmt_attach(self, msgbody):
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

    async def _fmt_auth(self, msgbody):
        afid = msgbody[0:4]
        unamelen = extract(msgbody, 4, 2)
        uname = msgbody[6:6+unamelen]

        anamelen = extract(msgbody, 6+unamelen, 2)
        aname = msgbody[8+unamelen:8+unamelen+anamelen]

        aqid = await self.auth(afid, uname, aname)

        return 13, c.RAUTH, (aqid,)
    async def auth(self, afid, uname, aname):
        raise NotImplementedError

    async def _fmt_stat(self, msgbody):
        fid = msgbody[0:4]
        statres = await self.stat(fid)
        statbytes = statres.to_bytes(with_envelope=True)
        return len(statbytes), c.RSTAT, (statbytes,)
    async def stat(self, fid):
        raise NotImplementedError

    async def _fmt_clunk(self, msgbody):
        fid = msgbody[0:4]
        await self.clunk(fid)
        return 0, c.RCLUNK, ()
    async def clunk(self, fid):
        raise NotImplementedError

    async def _fmt_walk(self, msgbody):
        fid = msgbody[0:4]
        newfid = msgbody[4:8]
        count = extract(msgbody, 8, 2)
        try:
            wnames = extract_bytefields(msgbody, 10, count)
        except ValueError:
            self._logger.debug('Could not build walknames: Count %s, %s', count, msgbody[10:].hex())
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

    async def _fmt_open(self, msgbody):
        fid = msgbody[0:4]
        mode = extract(msgbody, 4, 1)
        qid, iounit = await self.open(fid, mode)
        return 17, c.ROPEN, (qid, mkfield(iounit, 4))
    async def open(self, fid, mode):
        raise NotImplementedError

    async def _fmt_read(self, msgbody):
        fid = msgbody[0:4]
        offset = extract(msgbody, 4, 8)
        count = extract(msgbody, 12, 4)
        resdata = await self.read(fid, offset, count)
        #TODO: Length overflow checking
        resdatalen = len(resdata)
        return 4 + resdatalen, c.RREAD, (mkfield(resdatalen, 4), resdata)
    async def read(self, fid, offset, count):
        raise NotImplementedError

    async def _fmt_write(self, msgbody):
        fid = msgbody[0:4]
        offset = extract(msgbody, 4, 8)
        count = extract(msgbody, 12, 4)
        #TODO: Check that count matches the size
        data = msgbody[16:16+count]
        rescount = await self.write(fid, offset, data)
        return 4, c.RWRITE, (mkfield(rescount, 4),)
    async def write(self, fid, offset, data):
        raise NotImplementedError

    async def _fmt_create(self, msgbody):
        fid = msgbody[0:4]
        namelen = extract(msgbody, 4, 2)
        name = msgbody[6:6+namelen]

        perm = extract(msgbody, 6+namelen, 4)
        mode = extract(msgbody, 10+namelen, 1)
        qid, iounit = await self.create(fid, name, perm, mode)
        return 17, c.RCREATE, (qid, mkfield(iounit, 4))
    async def create(self, fid, name, perm, mode):
        raise NotImplementedError

    async def _fmt_wstat(self, msgbody):
        fid = msgbody[0:4]
        stat = Py9PStat.from_bytes(msgbody, 6)
        await self.wstat(fid, stat)
        return 0, c.RWSTAT, ()
    async def wstat(self, fid, stat):
        raise NotImplementedError

    async def _fmt_remove(self, msgbody):
        fid = msgbody[0:4]
        await self.remove(fid)
        return 0, c.RREMOVE, ()
    async def remove(self, fid):
        raise NotImplementedError
