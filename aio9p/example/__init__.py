
from asyncio import run, get_running_loop

from aio9p.protocol import Py9PProtocol

async def example_server(implementation):
    loop = get_running_loop()
    print('Hello')
    server = await loop.create_server(
        lambda: Py9PProtocol(implementation(1024))
        , '127.0.0.1'
        , 8090
        )
    async with server:
        await server.serve_forever()

def example_main(implementation):
    run(example_server(implementation))
