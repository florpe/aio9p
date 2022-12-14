
from dataclasses import asdict

from aio9p.constant import DMDIR
from aio9p.helper import mkqid
from aio9p.stat import Py9P2000Stat


# QID = QTByteDIR + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x00'
MODE = DMDIR | 0o777
QID = mkqid(MODE, b'\x00\x00\x00\x00\x00\x00\x00\x00')
STAT = Py9P2000Stat(
    p9type=0
    , p9dev=0
    , p9qid=QID
    , p9mode=MODE
    , p9atime=0
    , p9mtime=0
    , p9length=0
    , p9name=b'foodir'
    , p9uid=b'root'
    , p9gid=b'root'
    , p9muid=b'root'
    )

STAT2 = Py9P2000Stat(
    p9type=0
    , p9dev=0
    , p9qid=QID
    , p9mode=MODE
    , p9atime=0
    , p9mtime=123
    , p9length=0
    , p9name=b''
    , p9uid=b''
    , p9gid=b''
    , p9muid=b'nobody'
    )

STAT3 = Py9P2000Stat(
    p9type=0
    , p9dev=0
    , p9qid=QID
    , p9mode=MODE
    , p9atime=0
    , p9mtime=123
    , p9length=0
    , p9name=b'foodir'
    , p9uid=b'root'
    , p9gid=b'root'
    , p9muid=b'nobody'
    )

def test_identity():
    stat_serialized = STAT.to_bytes()
    stat_parsed = Py9P2000Stat.from_bytes(stat_serialized, 0)
    pdict = asdict(stat_parsed)
    sdict = asdict(STAT)
    assert stat_parsed == STAT
    assert stat_serialized == stat_parsed.to_bytes()

def test_wstat():
    assert STAT.wstat(STAT2) == STAT3
