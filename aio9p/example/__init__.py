
'''
A common wrapper for the example servers.
'''

from asyncio import run, get_running_loop, sleep as asleep
from logging import getLogger, StreamHandler, Formatter

from aio9p.protocol import Py9PProtocol

async def example_server(implementation):
    '''
    Wrapper for the example servers: Setup and logging.
    '''
    loop = get_running_loop()
    logger = getLogger('example-9p')
    handler = StreamHandler()
    fmt = Formatter('Logger: %(message)s')
    logger.setLevel('DEBUG')
    handler.setLevel('DEBUG')
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    server = await loop.create_server(
        lambda: Py9PProtocol(implementation(65535, logger=logger), logger=logger)
        , '127.0.0.1'
        , 8090
        )
    async with server:
        await server.start_serving()
        logger.info('Server is running')
        while True:
            await asleep(3600)

def example_main(implementation):
    '''
    Running the server.
    '''
    run(example_server(implementation))
