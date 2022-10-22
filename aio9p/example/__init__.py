
from asyncio import run, get_running_loop
from logging import getLogger, StreamHandler, Formatter

from aio9p.protocol import Py9PProtocol

async def example_server(implementation):
    print('Example server running')
    loop = get_running_loop()
    logger = getLogger('example-9p')
    handler = StreamHandler()
    fmt = Formatter('Logger: %(message)s')
    logger.setLevel('DEBUG')
    handler.setLevel('DEBUG')
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    server = await loop.create_server(
        lambda: Py9PProtocol(implementation(1024, logger=logger), logger=logger)
        , '127.0.0.1'
        , 8090
        )
    async with server:
        await server.serve_forever()

def example_main(implementation):
    run(example_server(implementation))
