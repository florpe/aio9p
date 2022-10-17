
from dataclasses import dataclass, asdict

from aio9p.helper import extract, mkfield

@dataclass
class Py9PStat:
    p9type: int # [2:4]
    p9dev: int # [4:8]
    p9qid: bytes # [8:21]
    p9mode: int # [21:25]
    p9atime: int # [25:29]
    p9mtime: int # [29:33]
    p9length: int # [33:41]
    p9name: bytes # [s]
    p9uid: bytes # [s]
    p9gid: bytes # [s]
    p9muid: bytes # [s]

    def size(self):
        return 49 + len(self.p9name) + len(self.p9uid) + len(self.p9gid) + len(self.p9muid)
    @staticmethod
    def from_stat(stat, qid):
        raise NotImplementedError
    @staticmethod
    def from_bytes(inpt, offset):
        nameoffset = offset + 41
        namelen = extract(inpt, nameoffset, 2)
        uidoffset = nameoffset + 2 + namelen
        uidlen = extract(inpt, uidoffset, 2)
        gidoffset = uidoffset + 2 + uidlen
        gidlen = extract(inpt, gidoffset, 2)
        muidoffset = gidoffset + 2 + gidlen
        muidlen = extract(inpt, muidoffset, 2)
        return Py9PStat(
            p9type=extract(inpt, offset+2, 2)
            , p9dev=extract(inpt, offset+4, 4)
            , p9qid=inpt[offset+8:offset+21]
            , p9mode=extract(inpt, offset+21, 4)
            , p9atime=extract(inpt, offset+25, 4)
            , p9mtime=extract(inpt, offset+29, 4)
            , p9length=extract(inpt, offset+33, 8)
            , p9name=inpt[nameoffset+2:nameoffset+2+namelen]
            , p9uid=inpt[uidoffset+2:uidoffset+2+uidlen]
            , p9gid=inpt[gidoffset+2:gidoffset+2+gidlen]
            , p9muid=inpt[muidoffset+2:muidoffset+2+muidlen]
            )
    def to_bytes(self, with_envelope=False):
        namelen = len(self.p9name)
        uidlen = len(self.p9uid)
        gidlen = len(self.p9gid)
        muidlen = len(self.p9muid)

        totallen = 49 + namelen + uidlen + gidlen + muidlen
        return b''.join((
            mkfield(totallen, 2) if with_envelope else b''
            , mkfield(totallen-2, 2) #Size field of the stat struct
            , mkfield(self.p9type, 2)
            , mkfield(self.p9dev, 4)
            , self.p9qid
            , mkfield(self.p9mode, 4)
            , mkfield(self.p9atime, 4)
            , mkfield(self.p9mtime, 4)
            , mkfield(self.p9length, 8)
            , mkfield(namelen, 2)
            , self.p9name
            , mkfield(uidlen, 2)
            , self.p9uid
            , mkfield(gidlen, 2)
            , self.p9gid
            , mkfield(muidlen, 2)
            , self.p9muid
            ))
    def to_dict(self):
        return asdict(self)
