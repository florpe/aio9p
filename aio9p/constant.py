
'''
A central reference for the constants used by 9P.
'''

ENCODING = 'utf-8'

NOTAG = b'\xff\xff'
NOFID = b'\xff\xff'

# Open modes
OREAD = 0
OWRITE = 1
ORDWR = 2
OEXEC = 3

# QID types
QTDIR = 1 << 7
QTAPPEND = 1 << 6
QTEXCL = 1 << 5
QTHISTORIC = 1 << 4
QTAUTH = 1 << 3
QTTMP = 1 << 2
QTSYMLINK = 1 << 1
QTLINK = 1 << 0
QTFILE = 0

# QID types shifted for use with access modes
DMDIR = QTDIR << 24
DMAPPEND = QTAPPEND << 24
DMEXCL = QTEXCL << 24
DMHISTORIC = QTHISTORIC << 24
DMAUTH = QTAUTH << 24
DMTMP = QTTMP << 24
DMSYMLINK = QTSYMLINK << 24
DMLINK = QTLINK << 24
DMFILE = QTFILE << 24
# 9P2000.u extensions
U_DMDEVICE =  1 << 23
U_DMNAMEDPIPE = 1 << 21
U_DMSOCKET = 1 << 20
U_DMSETUID = 1 << 19
U_DMSETGID = 1 << 18

# QID types as single bytes
QTByteDIR = QTDIR.to_bytes(1, 'little')
QTByteAPPEND = QTAPPEND.to_bytes(1, 'little')
QTByteEXCL = QTEXCL.to_bytes(1, 'little')
QTByteAUTH = QTAUTH.to_bytes(1, 'little')
QTByteTMP = QTTMP.to_bytes(1, 'little')
QTByteSYMLINK = QTSYMLINK.to_bytes(1, 'little')
QTByteLINK = QTLINK.to_bytes(1, 'little')
QTByteFILE = QTFILE.to_bytes(1, 'little')

# Message types

TLERROR = 6
RLERROR = (TLERROR + 1)
TSTATFS = 8
RSTATFS = (TSTATFS + 1)
TLOPEN = 12
RLOPEN = (TLOPEN + 1)
TLCREATE = 14
RLCREATE = (TLCREATE + 1)
TSYMLINK = 16
RSYMLINK = (TSYMLINK + 1)
TMKNOD = 18
RMKNOD = (TMKNOD + 1)
TRENAME = 20
RRENAME = (TRENAME + 1)
TREADLINK = 22
RREADLINK = (TREADLINK + 1)
TGETATTR = 24
RGETATTR = (TGETATTR + 1)
TSETATTR = 26
RSETATTR = (TSETATTR + 1)
TXATTRWALK = 30
RXATTRWALK = (TXATTRWALK + 1)
TXATTRCREATE = 32
RXATTRCREATE = (TXATTRCREATE + 1)
TREADDIR = 40
RREADDIR = (TREADDIR + 1)
TFSYNC = 50
RFSYNC = (TFSYNC + 1)
TLOCK = 52
RLOCK = (TLOCK + 1)
TGETLOCK = 54
RGETLOCK = (TGETLOCK + 1)
TLINK = 70
RLINK = (TLINK + 1)
TMKDIR = 72
RMKDIR = (TMKDIR + 1)
TRENAMEAT = 74
RRENAMEAT = (TRENAMEAT + 1)
TUNLINKAT = 76
RUNLINKAT = (TUNLINKAT + 1)
TVERSION = 100
RVERSION = (TVERSION + 1)
TAUTH = 102
RAUTH = (TAUTH + 1)
TATTACH = 104
RATTACH = (TATTACH + 1)
TERROR = 106
RERROR = (TERROR + 1)
TFLUSH = 108
RFLUSH = (TFLUSH + 1)
TWALK = 110
RWALK = (TWALK + 1)
TOPEN = 112
ROPEN = (TOPEN + 1)
TCREATE = 114
RCREATE = (TCREATE + 1)
TREAD = 116
RREAD = (TREAD + 1)
TWRITE = 118
RWRITE = (TWRITE + 1)
TCLUNK = 120
RCLUNK = (TCLUNK + 1)
TREMOVE = 122
RREMOVE = (TREMOVE + 1)
TSTAT = 124
RSTAT = (TSTAT + 1)
TWSTAT = 126
RWSTAT = (TWSTAT + 1)


TRNAME = {
    TLERROR: "TLERROR"
    , RLERROR: "RLERROR"
    , TSTATFS: "TSTATFS"
    , RSTATFS: "RSTATFS"
    , TLOPEN: "TLOPEN"
    , RLOPEN: "RLOPEN"
    , TLCREATE: "TLCREATE"
    , RLCREATE: "RLCREATE"
    , TSYMLINK: "TSYMLINK"
    , RSYMLINK: "RSYMLINK"
    , TMKNOD: "TMKNOD"
    , RMKNOD: "RMKNOD"
    , TRENAME: "TRENAME"
    , RRENAME: "RRENAME"
    , TREADLINK: "TREADLINK"
    , RREADLINK: "RREADLINK"
    , TGETATTR: "TGETATTR"
    , RGETATTR: "RGETATTR"
    , TSETATTR: "TSETATTR"
    , RSETATTR: "RSETATTR"
    , TXATTRWALK: "TXATTRWALK"
    , RXATTRWALK: "RXATTRWALK"
    , TXATTRCREATE: "TXATTRCREATE"
    , RXATTRCREATE: "RXATTRCREATE"
    , TREADDIR: "TREADDIR"
    , RREADDIR: "RREADDIR"
    , TFSYNC: "TFSYNC"
    , RFSYNC: "RFSYNC"
    , TLOCK: "TLOCK"
    , RLOCK: "RLOCK"
    , TGETLOCK: "TGETLOCK"
    , RGETLOCK: "RGETLOCK"
    , TLINK: "TLINK"
    , RLINK: "RLINK"
    , TMKDIR: "TMKDIR"
    , RMKDIR: "RMKDIR"
    , TRENAMEAT: "TRENAMEAT"
    , RRENAMEAT: "RRENAMEAT"
    , TUNLINKAT: "TUNLINKAT"
    , RUNLINKAT: "RUNLINKAT"
    , TVERSION: "TVERSION"
    , RVERSION: "RVERSION"
    , TAUTH: "TAUTH"
    , RAUTH: "RAUTH"
    , TATTACH: "TATTACH"
    , RATTACH: "RATTACH"
    , TERROR: "TERROR"
    , RERROR: "RERROR"
    , TFLUSH: "TFLUSH"
    , RFLUSH: "RFLUSH"
    , TWALK: "TWALK"
    , RWALK: "RWALK"
    , TOPEN: "TOPEN"
    , ROPEN: "ROPEN"
    , TCREATE: "TCREATE"
    , RCREATE: "RCREATE"
    , TREAD: "TREAD"
    , RREAD: "RREAD"
    , TWRITE: "TWRITE"
    , RWRITE: "RWRITE"
    , TCLUNK: "TCLUNK"
    , RCLUNK: "RCLUNK"
    , TREMOVE: "TREMOVE"
    , RREMOVE: "RREMOVE"
    , TSTAT: "TSTAT"
    , RSTAT: "RSTAT"
    , TWSTAT: "TWSTAT"
    , RWSTAT: "RWSTAT"
    }
