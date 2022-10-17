
from asyncio import run, sleep as asleep, get_running_loop

from aio9p.protocol import Py9PProtocol, Py9P2000
from aio9p.example.simple import Simple9P

def fakewrite(conn, arg):
    print(arg)
    conn.sendall(b''.join(arg))

async def main():
    loop = get_running_loop()
    print('Hello')
    server = await loop.create_server(
        lambda: Py9PProtocol(Py9P2000(1024))
        , '127.0.0.1'
        , 8090
        )
    async with server:
        await server.serve_forever()




if __name__ == "__main__":
    run(main())
