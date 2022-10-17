
from dataclasses import asdict

from aio9p.constant import QTDIR, QTFILE
from aio9p.stat import Py9PStat


QID = QTDIR + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x00'
STAT = Py9PStat(
    p9type=0
    , p9dev=0
    , p9qid=QID
    , p9mode=int.from_bytes(b'\xff\xf0\x00'+QTDIR, 'little')
    , p9atime=0
    , p9mtime=0
    , p9length=0
    , p9name=b'foodir'
    , p9uid=b'root'
    , p9gid=b'root'
    , p9muid=b'root'
    )

def test_identity():
    stat_serialized = STAT.to_bytes()
    stat_parsed = Py9PStat.from_bytes(stat_serialized, 0)
    print('@')
    print('@  Serialized once:', stat_serialized.hex())
    print('@ Serialized twice:', stat_parsed.to_bytes().hex())

    pdict = asdict(stat_parsed)
    sdict = asdict(STAT)
    for k, v in pdict.items():
        print('@@', k, v, sdict[k])
    assert stat_parsed == STAT
    assert stat_serialized == stat_parsed.to_bytes()
