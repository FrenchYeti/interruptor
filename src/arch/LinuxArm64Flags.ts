


export const O_ = {
    O_ACCMODE: 0o00000003,
    O_RDONLY: 0o0000000,
    O_WRONLY: 0o0000001,
    O_RDWR	: 0o0000002,
    O_CREAT	: 0o0000100,
    O_EXCL	: 0o0000200,
    O_NOCTTY: 0o0000400,
    O_TRUNC	: 0o0001000,
    O_APPEND: 0o0002000,
    O_NONBLOCK: 0o0004000,
    O_DSYNC	: 0o0010000,
    O_ASYNC	: 0o0020000,
    O_DIRECT: 0o0040000,
    O_LARGEFILE: 0o0100000,
    O_DIRECTORY: 0o0200000,
    O_NOFOLLOW: 0o0400000,
    O_NOATIME: 0o1000000,
    O_CLOEXEC: 0o2000000,
    O_PATH:    0o10000000,
    O_TMPFILE: 0o20040000
};

export const MADV_ = {
    MADV_NORMAL: [0],
    MADV_RANDOM: [1],
    MADV_SEQUENTIAL: [2],
    MADV_WILLNEED: [3],
    MADV_DONTNEED: [4],
    MADV_FREE: [8],
    MADV_REMOVE: [9],
    MADV_DONTFORK: [10],
    MADV_DOFORK: [11],
    MADV_HWPOISON: [100],
    MADV_SOFT_OFFLINE: [101],
    MADV_MERGEABLE: [12],
    MADV_UNMERGEABLE: [13],
    MADV_HUGEPAGE: [14],
    MADV_NOHUGEPAGE: [15],
    MADV_DONTDUMP: [16],
    MADV_DODUMP: [17],
    MADV_WIPEONFORK: [18],
    MADV_KEEPONFORK: [19],
    MADV_COLD: [20],
    MADV_PAGEOUT: [21]
};
export const MS_ = {
    MS_ASYNC: 1,
    MS_INVALIDATE: 2,
    MS_SYNC: 4
};
export const MCL_ = {
    MCL_CURRENT: 1,
    MCL_FUTURE: 2,
    MCL_ONFAULT: 4
};
export const MAP_ = {
    MAP_SHARED: [0x01],
    MAP_PRIVATE: [0x02],
    MAP_SHARED_VALIDATE: [0x03],
    MAP_FIXED: [0x10],
    MAP_ANONYMOUS: [0x20],
    MAP_GROWSDOWN: [0x0100],
    MAP_DENYWRITE: [0x0800],
    MAP_EXECUTABLE: [0x1000],
    MAP_LOCKED: [0x2000],
    MAP_NORESERVE: [0x4000],
};


export const MNT_ = {
    MNT_FORCE: 1,
    MNT_DETACH: 2,
    MNT_EXPIRE: 4,
    UMOUNT_NOFOLLOW: 8,
};
const PROT_NONE = 0;
export const PROT_ = {
    PROT_READ: 1,
    PROT_WRITE: 2,
    PROT_EXEC: 4,
};
export const MFD = {
    MFD_CLOEXEC: 1,
    MFD_ALLOW_SEALING: 2,
    MFD_HUGETLB: 4,
};
export const AT_ = {
    AT_FDCWD: -100,
    AT_SYMLINK_NOFOLLOW: [0x100],
    AT_EACCESS: [0x200],
    AT_REMOVEDIR: [0x200],
    AT_SYMLINK_FOLLOW: [0x400],
    AT_NO_AUTOMOUNT: [0x800],
    AT_EMPTY_PATH: [0x1000],
    AT_STATX_SYNC_TYPE: [0x6000],
    AT_STATX_SYNC_AS_STAT: [0x0000],
    AT_STATX_FORCE_SYNC: [0x2000],
    AT_STATX_DONT_SYNC: [0x4000],
    AT_RECURSIVE: [0x8000],
}



const F_ = {
    F_DUPFD: [0],
    F_GETFD: [1],
    F_SETFD: [2],
    F_GETFL: [3],
    F_SETFL: [4],
    F_SETOWN: [8],
    F_GETOWN: [9],
    F_SETSIG: [10],
    F_GETSIG: [11],
    F_GETLK: [12],
    F_SETLK: [13],
    F_SETLKW: [14],
    F_SETOWN_EX: [15],
    F_GETOWN_EX: [16],
    F_GETOWNER_UIDS: [17]
}
/**
 * A function to stringify bitmap
 */
function stringifyBitmap(val:number, flags:any):string{
    let s = "";
    for(const f in flags){
        if((val & flags[f]) == flags[f]) s += (s.length>0?" | ":"")+f;
    }

    return s;
}

export const I = {
    KILL_FROM: function(ctx){
        const f = ctx.x0.toInt32();
        if(f>0){
            return f+" (target process)";
        }
        else if(f < 0){
            return f+" (all authorized processes)";
        }
        else{
            return f+" (all processes from process group of calling process)";
        }
    }
}

// signals : https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/include/uapi/asm-generic/signal.h
export const S = {
    SIGHUP: [1],
    SIGINT: [2],
    SIGQUIT: [3],
    SIGILL: [4],
    SIGTRAP: [5],
    SIGABRT: [6],
    SIGIOT: [6],
    SIGBUS: [7],
    SIGFPE: [8],
    SIGKILL: [9],
    SIGUSR1: [10],
    SIGSEGV: [11],
    SIGUSR2: [12],
    SIGPIPE: [13],
    SIGALRM: [14],
    SIGTERM: [15],
    SIGSTKFLT: [16],
    SIGCHLD: [17],
    SIGCONT: [18],
    SIGSTOP: [19],
    SIGTSTP: [20],
    SIGTTIN: [21],
    SIGTTOU: [22],
    SIGURG: [23],
    SIGXCPU: [24],
    SIGXFSZ: [25],
    SIGVTALRM: [26],
    SIGPROF: [27],
    SIGWINCH: [28],
    SIGIO: [29],
    // SIGPOLL		SIGIO
    // SIGLOST: [29],
    SIGPWR: [30],
    SIGSYS: [31],
    SIGUNUSED: [31],
    SIGRTMIN: [32],
    SIGRTMAX: [64], // 32 on arm32
    MINSIGSTKSZ: [2048],
    SIGSTKSZ: [8192],
};

//
export const E = {
	EPERM : [1,"Not super-user"],
	ENOENT : [2,"No such file or directory"],
	ESRCH : [3,"No such process"],
	EINTR : [4,"Interrupted system call"],
	EIO : [5,"I/O error"],
	ENXIO : [6,"No such device or address"],
	E2BIG : [7,"Arg list too long"],
	ENOEXEC : [8,"Exec format error"],
	EBADF : [9,"Bad file number"],
	ECHILD : [10,"No children"],
	EAGAIN : [11,"No more processes"],
	ENOMEM : [12,"Not enough core"],
	EACCES : [13,"Permission denied"],
	EFAULT : [14,"Bad address"],
	ENOTBLK : [15,"Block device required"],
	EBUSY : [16,"Mount device busy"],
	EEXIST : [17,"File exists"],
	EXDEV : [18,"Cross-device link"],
	ENODEV : [19,"No such device"],
	ENOTDIR : [20,"Not a directory"],
	EISDIR : [21,"Is a directory"],
	EINVAL : [22,"Invalid argument"],
	ENFILE : [23,"Too many open files in system"],
	EMFILE : [24,"Too many open files"],
	ENOTTY : [25,"Not a typewriter"],
	ETXTBSY : [26,"Text file busy"],
	EFBIG : [27,"File too large"],
	ENOSPC : [28,"No space left on device"],
	ESPIPE : [29,"Illegal seek"],
	EROFS : [30,"Read only file system"],
	EMLINK : [31,"Too many links"],
	EPIPE : [32,"Broken pipe"],
	EDOM : [33,"Math arg out of domain of func"],
	ERANGE : [34,"Math result not representable"],
	ENOMSG : [35,"No message of desired type"],
	EIDRM : [36,"Identifier removed"],
	ECHRNG : [37,"Channel number out of range"],
	EL2NSYNC : [38,"Level 2 not synchronized"],
	EL3HLT : [39,"Level 3 halted"],
	EL3RST : [40,"Level 3 reset"],
	ELNRNG : [41,"Link number out of range"],
	EUNATCH : [42,"Protocol driver not attached"],
	ENOCSI : [43,"No CSI structure available"],
	EL2HLT : [44,"Level 2 halted"],
	EDEADLK : [45,"Deadlock condition"],
	ENOLCK : [46,"No record locks available"],
    EBADE : [50,"Invalid exchange"],
    EBADR : [51,"Invalid request descriptor"],
    EXFULL : [52,"Exchange full"],
    ENOANO : [53,"No anode"],
    EBADRQC : [54,"Invalid request code"],
    EBADSLT : [55,"Invalid slot"],
    EDEADLOCK : [56,"File locking deadlock error"],
    EBFONT : [57,"Bad font file fmt"],
    ENOSTR : [60,"Device not a stream"],
    ENODATA : [61,"No data (for no delay io)"],
    ETIME : [62,"Timer expired"],
    ENOSR : [63,"Out of streams resources"],
    ENONET : [64,"Machine is not on the network"],
    ENOPKG : [65,"Package not installed"],
    EREMOTE : [66,"The object is remote"],
    ENOLINK : [67,"The link has been severed"],
    EADV : [68,"Advertise error"],
    ESRMNT : [69,"Srmount error"],
    ECOMM : [70,"Communication error on send"],
    EPROTO : [71,"Protocol error"],
    EMULTIHOP : [74,"Multihop attempted"],
    ELBIN : [75,"Inode is remote (not really error)"],
    EDOTDOT : [76,"Cross mount point (not really error)"],
    EBADMSG : [77,"Trying to read unreadable message"],
    EFTYPE : [79,"Inappropriate file type or format"],
    ENOTUNIQ : [80,"Given log. name not unique"],
    EBADFD : [81,"f.d. invalid for this operation"],
    EREMCHG : [82,"Remote address changed"],
    ELIBACC : [83,"Can't access a needed shared lib"],
    ELIBBAD : [84,"Accessing a corrupted shared lib"],
    ELIBSCN : [85,".lib section in a.out corrupted"],
    ELIBMAX : [86,"Attempting to link in too many libs"],
    ELIBEXEC : [87,"Attempting to exec a shared library"],
    ENOSYS : [88,"Function not implemented"],
    ENMFILE : [89,"No more files"],
    ENOTEMPTY : [90,"Directory not empty"],
    ENAMETOOLONG : [91,"File or path name too long"],
    ELOOP : [92,"Too many symbolic links"],
    EOPNOTSUPP : [95,"Operation not supported on transport endpoint"],
    EPFNOSUPPORT : [96,"Protocol family not supported"],
    ECONNRESET : [104,"Connection reset by peer"],
    ENOBUFS : [105,"No buffer space available"],
    EAFNOSUPPORT : [106,"Address family not supported by protocol family"],
    EPROTOTYPE : [107,"Protocol wrong type for socket"],
    ENOTSOCK : [108,"Socket operation on non-socket"],
    ENOPROTOOPT : [109,"Protocol not available"],
    ESHUTDOWN : [110,"Can't send after socket shutdown"],
    ECONNREFUSED : [111,"Connection refused"],
    EADDRINUSE : [112,"Address already in use"],
    ECONNABORTED : [113,"Connection aborted"],
    ENETUNREACH : [114,"Network is unreachable"],
    ENETDOWN : [115,"Network interface is not configured"],
    ETIMEDOUT : [116,"Connection timed out"],
    EHOSTDOWN : [117,"Host is down"],
    EHOSTUNREACH : [118,"Host is unreachable"],
    EINPROGRESS : [119,"Connection already in progress"],
    EALREADY : [120,"Socket already connected"],
    EDESTADDRREQ : [121,"Destination address required"],
    EMSGSIZE : [122,"Message too long"],
    EPROTONOSUPPORT : [123,"Unknown protocol"],
    ESOCKTNOSUPPORT : [124,"Socket type not supported"],
    EADDRNOTAVAIL : [125,"Address not available"],
    ENETRESET : [126,""],
    EISCONN : [127,"Socket is already connected"],
    ENOTCONN : [128,"Socket is not connected"],
    ETOOMANYREFS :  [129,""],
    EPROCLIM : [130,""],
    EUSERS : [131,""],
    EDQUOT : [132,""],
    ESTALE : [133,""],
    ENOTSUP : [134,"Not supported"],
    ENOMEDIUM : [135,"No medium (in tape drive)"],
    ENOSHARE : [136,"No such host or network path"],
    ECASECLASH : [137,"Filename exists with different case"],
    EILSEQ : [138,""],
    EOVERFLOW : [139,"Value too large for defined data type"]
};

for(const k in E) E[k].push(k);

export const X = {
    RANGE: function(p){
        try{
            const m = Process.getModuleByAddress(p);
            return `${p} (${m!=null ? m.name : 'null'})`;
        }catch(e){
            return `${p}`;
        }
    },
    LINKAT: function(f){
        if(f == AT_.AT_SYMLINK_FOLLOW)
            return "AT_SYMLINK_FOLLOW";
        else
            return  0; // no flag
    },
    XATTR: function(f){
        return ["default","XATTR_CREATE","XATTR_REPLACE"][f];
    },
    FNCTL: function(f){
        for(const k in F_) if(f == F_[k][0]) return k;
        return null;
    },
    SIG: function(f){
        for(const k in S) if(f == S[k][0]) return k;
        return null;
    },
    MADV: function(f){
        for(const k in MADV_) if(f == MADV_[k][0]) return k;
        return null;
    },
    MCL: function(f){
        for(const k in MCL_) if(f == MCL_[k][0]) return k;
        return null;
    },
    MAP: function(f){
        return stringifyBitmap(f,MAP_);
    },
    MS: function(f){
        for(const k in MS_) if(f == MS_[k][0]) return k;
        return null;
    },
    ERR: function(f){
        for(const k in E) if(f == E[k][0]) return k+" /* "+E[k][1]+" */";
        return null;
    },
    ATTR: function(f){
        return f;
    },
    O_FLAG: function(f){
        return stringifyBitmap(f,O_);
    },
    O_MODE: function(f){
        return stringifyBitmap(f,O_);
    },
    UMOUNT: function(f){
        return stringifyBitmap(f,MNT_);
    },
    MFD: function(f){
        return stringifyBitmap(f,MFD);
    },
    MPROT: function(f){
        if(f == PROT_NONE)
            return "PROT_NONE";

        return stringifyBitmap(f,PROT_);
    },
}
