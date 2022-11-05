
'''
The interface between aio9p and asyncio.
'''

from asyncio import create_task, Task, Protocol, Semaphore, Event

import aio9p.constant as c
from aio9p.helper import extract, mkfield, NULL_LOGGER, MsgT, RspT

class Py9PException(Exception):
    '''
    Base class for Py9P-specific exceptions.
    '''
    pass

Py9PBadFID = Py9PException('Bad fid!')

class Py9PCommon(Protocol):
    '''
    Common ground between client and server implementations.
    '''
    _logger = NULL_LOGGER
    _buffer = b''
    _transport = None
    def connection_made(self, transport):
        '''
        Storing the transport.
        '''
        self._logger.info('Connection made')
        self._transport = transport
        return None
    def connection_lost(self, exc):
        '''
        Notify, nothing else.
        '''
        if exc is None:
            self._logger.info('Connection terminated')
        else:
            self._logger.info('Lost connection: %s', exc)
        return None
    def eof_received(self):
        '''
        Notify, nothing else.
        '''
        self._logger.info('End of file received')
        return None
    def data_received(self, data):
        '''
        Splitting incoming data into messages and processing these.
        '''
        self._logger.debug('Data received: %s', data)
        buffer = self._buffer + data
        buflen = len(buffer)
        msgstart = 0
        while msgstart < buflen - 7:
            msgsize = extract(buffer, msgstart, 4)
            msgend = msgstart + msgsize
            if buflen < msgend:
                break
            msgtype = extract(buffer, msgstart+4, 1)
            msgtag = buffer[msgstart+5:msgstart+7]
            msgbody = buffer[msgstart+7:msgend]
            self._process_incoming(msgtype, msgtag, msgbody)
            msgstart = msgend
        self._buffer = buffer[msgstart:]
        return None
    def _process_incoming(self, msgtype, msgtag, msgbody):
        '''
        Abstract method used to process incoming data.
        '''
        raise NotImplementedError

class Py9PServer(Py9PCommon):
    '''
    An asyncio protocol subclass for the 9P protocol.
    '''
    def __init__(self, implementation, logger=None):
        '''
        Replacing the default null logger and setting a tiny default
        message size.
        '''
        super().__init__()
        if logger is not None:
            self._logger = logger
        self.implementation = implementation

        self._transport = None

        self._tasks = {}

        return None
    def _process_incoming(self, msgtype, msgtag, msgbody):
        '''
        Parses message headers and sets up tasks to process
        the bodies. FLUSH is handled immediately.
        '''
        if msgtype == c.TFLUSH:
            self.flush(msgtag, msgbody)
            return None
        task = create_task(
            self.implementation.process_msg(msgtype, msgbody)
            )
        self._tasks[msgtag] = task
        task.add_done_callback(lambda x: self.sendmsg(msgtag, x))
        return None
    def flush(self, tag: bytes, oldtag: bytes) -> None:
        '''
        Cancels the task indicated by FLUSH, if necessary.
        '''
        task = self._tasks.pop(oldtag, None)
        if task is None or task.cancelled():
            pass
        else:
            task.cancel()
        self._transport.writelines((
            mkfield(7, 4)
            , mkfield(c.RFLUSH, 1)
            , tag
            ))
        return None
    def sendmsg(self, msgtag: bytes, task: Task):
        '''
        Callback for tasks that are done. Do nothing if cancelled, send an
        error message if an exception occurred, otherwise send the result.
        '''
        if task.cancelled():
            self._logger.debug('Sending message: cancelled task %s', msgtag)
            return None
        task_stored = self._tasks.pop(msgtag, None)
        if not task_stored == task:
            self._logger.debug('Sending message: Mismatched task %s', msgtag)
            raise ValueError(msgtag, task, task_stored)
        exception = task.exception()
        if exception is None:
            restype, reslen, fields = task.result()
        else:
            self._logger.info('Sending message: Got exception %s %s %s', msgtag, exception, task)
            reslen, restype, fields = self.implementation.errhandler(exception)
        res = (
            mkfield(reslen + 7, 4)
            , mkfield(restype, 1)
            , msgtag
            ) + fields
        self._logger.debug('Sending message: %s', b''.join(res).hex())
        self._transport.writelines(res)
        return None

class Py9PClient(Py9PCommon):
    '''
    A class for the client side of the 9P protocol.
    '''
    def __init__(self, logger=None, poolsize=0xFF):
        '''
        Replacing the default null logger and setting a tiny default
        message size.
        '''
        if logger is not None:
            self._logger = logger
        self._transport = None

        self._semaphore = Semaphore(poolsize)
        self._tags = set(
            mkfield(i, 2)
            for i in range(poolsize)
            )
        self._event = {
            tag: Event()
            for tag in self._tags
            }
        self._result = {
            tag: None
            for tag in self._tags
            }
        return None
    def connection_made(self, transport):
        '''
        Storing the transport.
        '''
        self._logger.info('Connection made')
        self._transport = transport
        return None
    def connection_lost(self, exc):
        '''
        Notify, nothing else.
        '''
        if exc is None:
            self._logger.info('Connection terminated')
        else:
            self._logger.info('Lost connection: %s', exc)
        return None
    def eof_received(self):
        '''
        Notify, nothing else.
        '''
        self._logger.info('End of file received')
        return None
    def _process_incoming(self, msgtype, msgtag, msgbody):
        '''
        Assign incoming messages to the correct event.
        '''
        if msgtag not in self._tags:
            self._logger.warn(
                'Unsolicited tag received: %s %s %s'
                , msgtype, msgtag, msgbody
                )
            return None
        self._result[msgtag] = (msgtype, msgbody)
        self._event[msgtag].set()
        return None
    async def message(self, msg: MsgT) -> RspT:
        '''
        Send a message and wait for the result.
        '''
        msgtype, msglen, fields = msg
        async with self._semaphore:
            tag = self._tags.pop()
            self._transport.writelines((
                mkfield(msglen + 7, 4)
                , mkfield(msgtype, 1)
                , tag
                ) + fields
                )
            await self._event[tag].wait()
            res = self._result.pop(tag)
            self._tags.add(tag)
            return res

class Py9P():
    '''
    A base class for Py9P implementations that are meant to interoperate
    with Py9PServer.
    '''
    async def process_msg(
        self
        , msgtype: int
        , msgbody: bytes
        ) -> MsgT:
        '''
        Exactly what it says on the tin.
        '''
        raise NotImplementedError
    def errhandler(self, exception: BaseException) -> MsgT:
        '''
        Exactly what it says on the tin.
        '''
        raise NotImplementedError
