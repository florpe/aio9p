
from asyncio import create_task, sleep as asleep
from inspect import currentframe, getframeinfo
from pytest import mark
import pytest_asyncio

from aio9p.dialect.client.Py9P2000 import Py9P2000Client
from aio9p.dialect.client.Py9P2000u import Py9P2000uClient
from aio9p.example import example_client, example_server, example_logger
from aio9p.example.simple import Simple9P2000
from aio9p.example.simple_u import Simple9P2000u

# pytest_plugins = ('pytest_asyncio',)

SERVERS = [
    (Simple9P2000, Py9P2000Client, 'plain')
    , (Simple9P2000u, Py9P2000uClient, 'dot-u')
    ]

LOGGER = example_logger()

def sockname(uniq):
    fi = getframeinfo(currentframe().f_back)
    path = fi.filename
    prefixstart = path.find('/tests/')
    if prefixstart is not None:
        path = path[prefixstart+7:]
    path = path.replace('/', '.')
    return f'pytest.{path}.{fi.function}.{fi.lineno}.{uniq}.sock'

@mark.parametrize('Server,Client,uniq', SERVERS)
@mark.asyncio
async def test_attach(Server, Client, uniq):
    sockpath = sockname(uniq)
    print(sockpath)
    logger = LOGGER.getChild(uniq)
    task = create_task(example_server(
        logger.getChild('server')
        , Server
        , sockpath=sockpath
        ))
    logger = logger.getChild('client')
    await asleep(1)
    try:
        async with Client(logger=logger, remote={'path': sockpath}) as client:
            logger.info('Negotiating for version %s', client.versionstring)
            await client.negotiate(client.versionstring, 65535)
            logger.info('Negotiation successful.')
            rootqid = await client.attach(
                b'\x00\x00\x00\x00'
                , b'\x00\x00\x00\x01'
                , b'root'
                , b'root'
                )
            logger.info('Attach successful: qid %s', rootqid)
        logger.info('Success!')
    finally:
        task.cancel()
