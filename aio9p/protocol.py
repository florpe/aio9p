
'''
The interface between aio9p and asyncio.
'''

from asyncio import create_task, Task, get_running_loop, Protocol, Semaphore, Event
from typing import Optional, Tuple

import aio9p.constant as c
from aio9p.helper import (
    extract
    , extract_bytefields
    , mkfield
    , mkbytefields
    , NULL_LOGGER
    , FieldsT
    , MsgT
    , RspT
    )

class Py9PException(Exception):
    '''
    Base class for Py9P-specific exceptions.
    '''
    pass
class Py9PError(Py9PException):
    '''
    Client exception: Expected message type, received
    message type, and body.
    '''
    def __init__(self, body, *args, **kwargs):
        '''
        Populating the fields.
        '''
        super().__init__(body, *args, **kwargs)
        for k, kwarg in kwargs.items():
            setattr(self, k, kwarg)
        self.body = body
        self.fields = args
        return None

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
            self._logger.debug(
                'Processing: Msgtype %s, tag %s , body %s'
                , msgtype, msgtag, msgbody
                )
            self._process_incoming(msgtype, msgtag, msgbody)
            msgstart = msgend
        self._buffer = buffer[msgstart:]
        return None
    def _process_incoming(self, msgtype: int, msgtag: bytes, msgbody: bytes):
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
        if self._transport is None:
            raise RuntimeError
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
        if self._transport is None:
            raise RuntimeError
        self._transport.writelines(res)
        return None


class Py9PClient(): # pylint: disable=too-many-instance-attributes
    '''
    A class for the client side of the 9P protocol.
    '''
    versionstring = b'9P'
    _logger = NULL_LOGGER
    def __init__( # pylint: disable=too-many-arguments
        self
        , remote
        , logger=None
        , maxsize=0xFFFF
        , poolsize=0xFF
        ):
        self._maxsize_preset = maxsize
        if logger is not None:
            self._logger = logger
        self._remote = remote
        connection = Py9PClientConnection(
            logger
            , self.errparser
            , maxsize
            , poolsize
            )
        self._connection = connection
        self.connect = connection.p9connect
        self.disconnect = connection.p9disconnect
        self.message = connection.message
    async def __aenter__(self):
        '''
        Sets up the underlying connection.
        '''
        await self.connect(self._remote)
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        '''
        Tears down the underlying connection.
        '''
        await self.disconnect()
        return None
    def errparser(
        self
        , tmsg_type: int
        , tmsg_fields: Tuple[bytes, ...]
        , errmsgbody: bytes
        ) -> Py9PError:
        '''
        Turns an error reply into an exception.
        '''
        (errmsg,) = extract_bytefields(errmsgbody, 0, 1)
        return Py9PError(
            errmsgbody
            , errmsg=errmsg
            , tmsg_type=tmsg_type
            , tmsg_fields=tmsg_fields
            )
    async def negotiate(
        self
        , versionstring: Optional[bytes] = None
        , maxsize: Optional[int] = None
        , additional_fields: FieldsT = ()
        ):
        '''
        A thin wrapper to optionally pass instance attributes
        to self._connection.negotiate .
        '''
        if maxsize is None:
            maxsize = self._maxsize_preset
        if versionstring is None:
            versionstring = self.versionstring
        return await self._connection.negotiate(
            versionstring
            , maxsize
            , additional_fields
            )

class Py9PClientConnection(Py9PCommon): # pylint: disable=too-many-instance-attributes
    '''
    A class for the client connection of the 9P protocol.
    '''
    _logger = NULL_LOGGER
    def __init__( # pylint: disable=too-many-arguments
        self
        , logger
        , errparser
        , maxsize
        , poolsize
        ):
        '''
        Replacing the default null logger and setting a tiny default
        message size.
        '''
        self._errparser = errparser
        self.maxsize = None
        self._maxsize_preset = maxsize
        poolsize = min(poolsize, 0xFFFF-1) #Exclude NOTAG from pool
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
        self._event[c.NOTAG] = Event()
        self._result = {
            tag: None
            for tag in self._tags
            }
        self._result[c.NOTAG] = None
        return None
    async def p9connect(self, remote):
        '''
        Sets up a TCP or UNIX domain socket connection. Does not
        run version negotiation.
        '''
        if 'path' in remote:
            await get_running_loop().create_unix_connection(
                lambda: self
                , **remote
                )
        else:
            await get_running_loop().create_connection(
                lambda: self
                , **remote
                )
        return None
    async def p9disconnect(self):
        '''
        Closes the transport gracefully.
        '''
        if self._transport is not None:
            self._transport.close()
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
    def _process_incoming(self, msgtype: int, msgtag: bytes, msgbody: bytes):
        '''
        Assign incoming messages to the correct event.
        '''
        if msgtag not in self._event and msgtag != c.NOTAG:
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
            if self._transport is None:
                raise RuntimeError
            self._transport.writelines((
                mkfield(msglen + 7, 4)
                , mkfield(msgtype, 1)
                , tag
                ) + fields
                )
            await self._event[tag].wait()
            msgtype, msgbody = self._result.pop(tag)
            self._tags.add(tag)
            if msgtype == c.RERROR:
                raise self._errparser(msgtype, fields, msgbody)
            return msgtype, msgbody
    async def negotiate(
        self
        , versionstring: bytes
        , maxsize: int
        , additional_fields: FieldsT = ()
        ):
        '''
        Negotiate for exactly `versionstring`. Returns the minimum of the
        client and server maximum message size together with the unparsed
        remainder of the response, which for 9P2000 and the .u and .L dialects
        is empty.
        '''
        cverlen, cverfields = mkbytefields(versionstring)
        reqlen = 4 + cverlen + sum(map(len, additional_fields), start=0)
        reqfields = (mkfield(maxsize, 4),) + cverfields + additional_fields
        if self._transport is None:
            raise RuntimeError
        self._transport.writelines((
            mkfield(reqlen + 7, 4)
            , mkfield(c.TVERSION, 1)
            , c.NOTAG
            ) + reqfields
            )
        await self._event[c.NOTAG].wait()
        restype, resbody = self._result[c.NOTAG]
        if restype != c.RVERSION:
            raise RuntimeError( #Should this be a Py9PException?
                'Version negotiation gone awry'
                , versionstring, maxsize, restype, resbody
                )
        srvverlen = extract(resbody, 4, 2)
        srvver = resbody[6:6+srvverlen]
        if srvver != versionstring:
            raise Py9PException('Version mismatch!', versionstring, srvver)
        srvsize = extract(resbody, 0, 4)
        self.maxsize = min(srvsize, maxsize)
        return self.maxsize, resbody[6+srvverlen:]

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
