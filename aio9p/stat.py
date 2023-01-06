
'''
Py9P stat structs.
'''

from dataclasses import dataclass, asdict, replace
from typing import Optional

from aio9p.helper import extract, mkfield, extract_bytefields


@dataclass
class Py9P2000Stat: # pylint: disable=too-many-instance-attributes
    '''
    A class to implement the Py9P2000 stat struct.
    '''
    p9type: Optional[int] = None # [2:4]
    p9dev: Optional[int] = None # [4:8]
    p9qid: Optional[bytes] = None # [8:21]
    p9mode: Optional[int] = None # [21:25]
    p9atime: Optional[int] = None # [25:29]
    p9mtime: Optional[int] = None # [29:33]
    p9length: Optional[int] = None # [33:41]
    p9name: Optional[bytes] = None # [s]
    p9uid: Optional[bytes] = None # [s]
    p9gid: Optional[bytes] = None # [s]
    p9muid: Optional[bytes] = None # [s]

    fieldsizes = {
        'p9type': 2
        , 'p9dev': 4
        , 'p9qid': None
        , 'p9mode': 4
        , 'p9atime': 4
        , 'p9mtime': 4
        , 'p9length': 8
        , 'p9name': None
        , 'p9uid': None
        , 'p9gid': None
        , 'p9muid': None
        }

    def __hash__(self):
        '''
        The identity of a filesystem entity is determined entirely by its qid.
        '''
        return hash(self.p9uid)
    def __post_init__(self):
        '''
        Fields that are not populated should be ignored by the protocol.
        '''
        for fieldname, fieldsize in self.fieldsizes.items():
            if getattr(self, fieldname) is not None:
                continue
            fielddefault = b'' if fieldsize is None else (256**fieldsize) - 1
            setattr(self, fieldname, fielddefault)
        return None
    def to_dict(self, filtered=False):
        '''
        Convenience method that returns the instance data in dict form.
        '''
        res = asdict(self)
        if not filtered:
            return res
        for fieldname, fieldsize in self.fieldsizes.items():
            fieldval = res[fieldname]
            if fieldsize is None:
                if not fieldval:
                    res.pop(fieldname, None)
            elif fieldval == (256**fieldsize) - 1:
                res.pop(fieldname, None)
        return res
    def size(self):
        '''
        Size calculation that respects the various envelopes.
        '''
        total = 0 # qid length minus envelope count
        for fieldname, fieldsize in self.fieldsizes.items():
            if fieldsize is None:
                total = total + 2 + len(getattr(self, fieldname))
            else:
                total = total + fieldsize
        return total
    def wstat(self, other):
        '''
        Return a version of `self` updated with values from `other`.
        '''
        if (
            other.p9mode != 256**self.fieldsizes.get('p9mode') - 1
            and (self.p9mode & 0o7777000) != (other.p9mode & 0o7777000)
            ):
            raise ValueError('Cannot change mode via wstat', self.p9mode, other.p9mode)
        return replace(self, **other.to_dict(filtered=True))
    @staticmethod
    def from_stat(stat, qid):
        '''
        Create an instance from a Python Stat object.
        '''
        raise NotImplementedError
    @staticmethod
    def from_bytes(inpt, offset):
        '''
        Parser.
        '''

        name, uid, gid, muid = extract_bytefields(inpt, offset+41, 4)

        return Py9P2000Stat(
            p9type=extract(inpt, offset+2, 2)
            , p9dev=extract(inpt, offset+4, 4)
            , p9qid=inpt[offset+8:offset+21]
            , p9mode=extract(inpt, offset+21, 4)
            , p9atime=extract(inpt, offset+25, 4)
            , p9mtime=extract(inpt, offset+29, 4)
            , p9length=extract(inpt, offset+33, 8)
            , p9name=name
            , p9uid=uid
            , p9gid=gid
            , p9muid=muid
            )
    def to_bytes(self, with_envelope=False):
        '''
        Formatter.
        '''
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

@dataclass
class Py9P2000uStat(Py9P2000Stat): # pylint: disable=too-many-instance-attributes
    '''
    A class to implement the Py9P2000.u stat struct.
    '''
    p9u_extension: Optional[bytes] = None# [s]
    p9u_n_uid: Optional[int] = None
    p9u_n_gid: Optional[int] = None
    p9u_n_muid: Optional[int] = None

    fieldsizes = {
        **Py9P2000Stat.fieldsizes
        , 'p9u_extension': None
        , 'p9u_n_uid': 4
        , 'p9u_n_gid': 4
        , 'p9u_n_muid': 4
        }
    @staticmethod
    def from_stat(stat, qid):
        '''
        Create an instance from a Python Stat object.
        '''
        raise NotImplementedError
    @staticmethod
    def from_bytes(inpt, offset):
        '''
        Parser.
        '''
        varfields = extract_bytefields(inpt, offset+41, 5)
        name, uid, gid, muid, extension = varfields
        n_offset = offset + 51 + sum((len(field) for field in varfields))

        return Py9P2000uStat(
            p9type=extract(inpt, offset+2, 2)
            , p9dev=extract(inpt, offset+4, 4)
            , p9qid=inpt[offset+8:offset+21]
            , p9mode=extract(inpt, offset+21, 4)
            , p9atime=extract(inpt, offset+25, 4)
            , p9mtime=extract(inpt, offset+29, 4)
            , p9length=extract(inpt, offset+33, 8)
            , p9name=name
            , p9uid=uid
            , p9gid=gid
            , p9muid=muid
            , p9u_extension=extension
            , p9u_n_uid=extract(inpt, n_offset, 4)
            , p9u_n_gid=extract(inpt, n_offset+4, 4)
            , p9u_n_muid=extract(inpt, n_offset+8, 4)
            )
    def to_bytes(self, with_envelope=False):
        '''
        Formatter.
        '''
        namelen = len(self.p9name)
        uidlen = len(self.p9uid)
        gidlen = len(self.p9gid)
        muidlen = len(self.p9muid)
        extensionlen = len(self.p9u_extension)

        totallen = 63 + namelen + uidlen + gidlen + muidlen + extensionlen
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
            , mkfield(extensionlen, 2)
            , self.p9u_extension
            , mkfield(self.p9u_n_uid, 4)
            , mkfield(self.p9u_n_gid, 4)
            , mkfield(self.p9u_n_muid, 4)
            ))
