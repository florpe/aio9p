
'''
Py9P stat structs.
'''

from dataclasses import dataclass, asdict

from aio9p.helper import extract, mkfield, extract_bytefields

@dataclass
class Py9P2000Stat: # pylint: disable=too-many-instance-attributes
    '''
    A class to implement the Py9P2000 stat struct.
    '''
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
        '''
        Size calculation that respects the various envelopes.
        '''
        return sum(
            49
            , len(self.p9name)
            , len(self.p9uid)
            , len(self.p9gid)
            , len(self.p9muid)
            )
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
    def to_dict(self):
        '''
        Convenience method that returns the instance data in dict form.
        '''
        return asdict(self)

@dataclass
class Py9P2000uStat(Py9P2000Stat): # pylint: disable=too-many-instance-attributes
    '''
    A class to implement the Py9P2000.u stat struct.
    '''
    p9u_extension: bytes # [s]
    p9u_n_uid: int
    p9u_n_gid: int
    p9u_n_muid: int

    def size(self):
        '''
        Size calculation that respects the various envelopes.
        '''
        return sum(
            63
            , len(self.p9name)
            , len(self.p9uid)
            , len(self.p9gid)
            , len(self.p9muid)
            , len(self.p9u_extension)
            )
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
        n_offset = offset + 51 + sum(len(field) for field in varfields)

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
    def to_dict(self):
        '''
        Convenience method that returns the instance data in dict form.
        '''
        return asdict(self)
