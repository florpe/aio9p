
'''
The interface between aio9p and asyncio.
'''

from asyncio import create_task, Task, Protocol

import aio9p.constant as c
from aio9p.helper import extract, mkfield, NULL_LOGGER, MsgT

class Py9PException(Exception):
    '''
    Base class for Py9P-specific exceptions.
    '''
    pass

Py9PBadFID = Py9PException('Bad fid!')

class Py9PProtocol(Protocol):
    '''
    An asyncio protocol subclass for the 9P protocol.
    '''
    _logger = NULL_LOGGER
    def __init__(self, implementation, logger=None):
        '''
        Replacing the default null logger and setting a tiny default
        message size.
        '''
        if logger is not None:
            self._logger = logger
        self.maxsize = 256 #Default, overwritten by version negotiation
        self.implementation = implementation

        self._transport = None

        self._tasks = {}
        self._buffer = b''

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
    def data_received(self, data):
        '''
        Parses message headers and sets up tasks to process
        the bodies. FLUSH is handled immediately.
        '''
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
            msgstart = msgend
        self._buffer = buffer[msgstart:]
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
            mkfield(7, 7)
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
        #TODO: Check message size
        res = (
            mkfield(reslen + 7, 4)
            , mkfield(restype, 1)
            , msgtag
            ) + fields
        self._logger.debug('Sending message: %s', b''.join(res).hex())
        self._transport.writelines(res)
        return None

class Py9P():
    '''
    A base class for Py9P implementations that are meant to interoperate
    with Py9PProtocol.
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
