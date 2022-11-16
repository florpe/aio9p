
'''
A common wrapper for the example servers.
'''

from asyncio import run, get_running_loop, sleep as asleep
from logging import getLogger, StreamHandler, Formatter
from os import remove

from aio9p.protocol import Py9PServer, Py9PClient

async def example_server(logger, implementation, sockpath='./py9p.sock'):
    '''
    Wrapper for the example servers.
    '''
    try:
        remove(sockpath)
    except FileNotFoundError:
        pass
    server = await get_running_loop().create_unix_server(
        lambda: Py9PServer(
            implementation(65535, logger=logger.getChild('implementation'))
            , logger=logger.getChild('server')
            )
        , path=sockpath
        )
    async with server:
        await server.start_serving()
        logger.info('Server is running')
        while True:
            await asleep(3600)

async def example_client(logger, client, sockpath='./py9p.sock'):
    '''
    Wrapper for the example clients.
    '''
    async with Py9PClient(
        logger=logger.getChild('client')
        , remote={'path': sockpath}
        ) as conn:
        await client(conn)
    return None

def example_logger():
    '''
    Setting up a basic logger.
    '''
    logger = getLogger()
    handler = StreamHandler()
    fmt = Formatter('%(name)s: %(message)s')
    logger.setLevel('DEBUG')
    handler.setLevel('DEBUG')
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger

def example_main(example, client=False):
    '''
    Running the example.
    '''
    logger = example_logger()
    if client:
        logger.info('Running client %s!', type(example).__name__)
        run(example_client(logger, example))
    else:
        logger.info('Running server %s!', type(example).__name__)
        run(example_server(logger, example))
    logger.info('Done!')
