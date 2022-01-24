

export const K = {
    P_ALL: [0],
    P_PID: [1],
    P_PGID: [2],
    P_PIDFD: [3]
}
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

export const PTRACE_ = {
    PTRACE_TRACEME: [0],
    PTRACE_PEEKTEXT: [1],
    PTRACE_PEEKDATA: [2],
    PTRACE_PEEKUSR: [3],
    PTRACE_POKETEXT: [4],
    PTRACE_POKEDATA: [5],
    PTRACE_POKEUSR: [6],
    PTRACE_CONT: [7],
    PTRACE_KILL: [8],
    PTRACE_SINGLESTEP: [9],
    PTRACE_ATTACH: [16],
    PTRACE_DETACH: [17],
    PTRACE_SYSCALL: [24],
    PTRACE_SETOPTIONS: [0x4200],
    PTRACE_GETEVENTMSG: [0x4201],
    PTRACE_GETSIGINFO: [0x4202],
    PTRACE_SETSIGINFO: [0x4203],
    PTRACE_GETREGSET: [0x4204],
    PTRACE_SETREGSET: [0x4205],
    PTRACE_SEIZE: [0x4206],
    PTRACE_INTERRUPT: [0x4207],
    PTRACE_LISTEN: [0x4208],
    PTRACE_PEEKSIGINFO: [0x4209]
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
export const PR_ = {
    OPT: {
        PR_CAP_AMBIENT: [47],
        PR_CAPBSET_READ: [23],
        PR_CAPBSET_DROP: [24],
        PR_SET_CHILD_SUBREAPER: [36],
        PR_GET_CHILD_SUBREAPER: [37],
        PR_SET_PDEATHSIG: [1],
        PR_GET_PDEATHSIG: [2],
        PR_GET_DUMPABLE: [3],
        PR_SET_DUMPABLE: [4],
        PR_GET_UNALIGN: [5],
        PR_SET_UNALIGN: [6],
        PR_GET_KEEPCAPS: [7],
        PR_SET_KEEPCAPS: [8],
        PR_GET_FPEMU: [9],
        PR_SET_FPEMU: [10],
        PR_GET_FPEXC: [11],
        PR_SET_FPEXC: [12],
        PR_GET_TIMING: [13],
        PR_SET_TIMING: [14],
        PR_SET_NAME: [15],
        PR_GET_NAME: [16],
        PR_GET_ENDIAN: [19],
        PR_SET_ENDIAN: [20],
        PR_GET_SECCOMP: [21],
        PR_SET_SECCOMP: [22],
        PR_GET_TSC: [25],
        PR_SET_TSC: [26],
        PR_GET_SECUREBITS: [27],
        PR_SET_SECUREBITS: [28],
        PR_SET_TIMERSLACK: [29],
        PR_GET_TIMERSLACK: [30],
        PR_SET_PTRACER: [0x59616d61],
        PR_SET_PTRACER_ANY: [(0xffffffffffffffff - 1)],
        PR_SET_NO_NEW_PRIVS: [38],
        PR_GET_NO_NEW_PRIVS: [39],
        PR_GET_TID_ADDRESS: [40],
        PR_SET_THP_DISABLE: [41],
        PR_GET_THP_DISABLE: [42],
        PR_SET_IO_FLUSHER: [57],
        PR_GET_IO_FLUSHER: [58],
        PR_SET_SYSCALL_USER_DISPATCH: [59],
        PR_SET_VMA: [0x53564d41],
        PR_SET_VMA_ANON_NAME: [0],
        PR_SET_TAGGED_ADDR_CTRL: [55],
        PR_GET_TAGGED_ADDR_CTRL: [56],
        PR_SET_MM: [35],
        PR_SET_FP_MODE: [45],
        PR_GET_FP_MODE: [46],
        PR_GET_SPECULATION_CTRL: [52],
        PR_SET_SPECULATION_CTRL: [53],
    },
    CAP: {
        PR_CAP_AMBIENT_IS_SET: [1],
        PR_CAP_AMBIENT_RAISE: [2],
        PR_CAP_AMBIENT_LOWER: [3],
        PR_CAP_AMBIENT_CLEAR_ALL: [4],
    },
    UNALIGN: {
        PR_UNALIGN_NOPRINT: [1],
        PR_UNALIGN_SIGBUS: [2],
    },
    FPEMU: {
        PR_FPEMU_NOPRINT: [1],
        PR_FPEMU_SIGFPE: [2],
    },
    FP: {
        PR_FP_EXC_SW_ENABLE: [0x80],
        PR_FP_EXC_DIV: [0x010000],
        PR_FP_EXC_OVF: [0x020000],
        PR_FP_EXC_UND: [0x040000],
        PR_FP_EXC_RES: [0x080000],
        PR_FP_EXC_INV: [0x100000],
        PR_FP_EXC_DISABLED: [0],
        PR_FP_EXC_NONRECOV: [1],
        PR_FP_EXC_ASYNC: [2],
        PR_FP_EXC_PRECISE: [3],
        PR_FP_MODE_FR: [(1 << 0)],
        PR_FP_MODE_FRE: [(1 << 1)],
    },
    TIMING: {
        PR_TIMING_STATISTICAL: [0],
        PR_TIMING_TIMESTAMP: [1],
    },
    ENDIAN: {
        PR_ENDIAN_BIG: [0],
        PR_ENDIAN_LITTLE: [1],
        PR_ENDIAN_PPC_LITTLE: [2],
    },
    TSC: {
        PR_TSC_ENABLE: [1],
        PR_TSC_SIGSEGV: [2],
    },
    TASK: {
        PR_TASK_PERF_EVENTS_DISABLE: [31],
        PR_TASK_PERF_EVENTS_ENABLE: [32],
    },
    MCE: {
        PR_MCE_KILL: [33],
        PR_MCE_KILL_CLEAR: [0],
        PR_MCE_KILL_SET: [1],
        PR_MCE_KILL_LATE: [0],
        PR_MCE_KILL_EARLY: [1],
        PR_MCE_KILL_DEFAULT: [2],
        PR_MCE_KILL_GET: [34],
    },
    MM: {
        PR_SET_MM_START_CODE: [1],
        PR_SET_MM_END_CODE: [2],
        PR_SET_MM_START_DATA: [3],
        PR_SET_MM_END_DATA: [4],
        PR_SET_MM_START_STACK: [5],
        PR_SET_MM_START_BRK: [6],
        PR_SET_MM_BRK: [7],
        PR_SET_MM_ARG_START: [8],
        PR_SET_MM_ARG_END: [9],
        PR_SET_MM_ENV_START: [10],
        PR_SET_MM_ENV_END: [11],
        PR_SET_MM_AUXV: [12],
        PR_SET_MM_EXE_FILE: [13],
        PR_SET_MM_MAP: [14],
        PR_SET_MM_MAP_SIZE: [15]
    },
    MPX: {
        PR_MPX_ENABLE_MANAGEMENT: [43],
        PR_MPX_DISABLE_MANAGEMENT: [44],
    },
    SVE: {
        PR_SVE_SET_VL: [50],
        PR_SVE_SET_VL_ONEXEC: [(1 << 18)],
        PR_SVE_GET_VL: [51],
        PR_SVE_VL_LEN_MASK: [0xffff],
        PR_SVE_VL_INHERIT: [(1 << 17)],
    },
    SPEC: {
        PR_SPEC_STORE_BYPASS: [0],
        PR_SPEC_INDIRECT_BRANCH: [1],
        PR_SPEC_NOT_AFFECTED: [0],
        PR_SPEC_PRCTL: [(1 << 0)],
        PR_SPEC_ENABLE: [(1 << 1)],
        PR_SPEC_DISABLE: [(1 << 2)],
        PR_SPEC_FORCE_DISABLE: [(1 << 3)],
        PR_SPEC_DISABLE_NOEXEC: [(1 << 4)],
    },
    PAC: {
        PR_PAC_RESET_KEYS: [54],
        PR_PAC_APIAKEY: [(1 << 0)],
        PR_PAC_APIBKEY: [(1 << 1)],
        PR_PAC_APDAKEY: [(1 << 2)],
        PR_PAC_APDBKEY: [(1 << 3)],
        PR_PAC_APGAKEY: [(1 << 4)],
    },
    TAGGED: {
        PR_TAGGED_ADDR_ENABLE: [(1 << 0)],
    },
    MTE: {
        PR_MTE_TCF_SHIFT: [1],
        PR_MTE_TAG_SHIFT: [3],
        PR_MTE_TCF_NONE: [(0 << 1)],
        PR_MTE_TCF_SYNC: [(1 << 1)],
        PR_MTE_TCF_ASYNC: [(2 << 1)],
        PR_MTE_TCF_MASK: [(3 << 1)],
        PR_MTE_TAG_MASK: [(0xffff << 3)],
    },
    SYS: {
        PR_SYS_DISPATCH_OFF: [0],
        PR_SYS_DISPATCH_ON: [1],
    },
    SYSCALL: {
        SYSCALL_DISPATCH_FILTER_ALLOW: [0],
        SYSCALL_DISPATCH_FILTER_BLOCK: [1]
    }
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
    PROT_SEM: 8, // arch sensitive
    // PROT_SAO: 0x10,  // not implemented on ARM ?
    PROT_GROWSDOWN: 0x01000000,
    PROT_GROWSUP: 0x02000000
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

function l( val, list){
    for(const k in list) if(val == list[k][0]) return k;
    return null;
}

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
    PRCTL_OPT: function(f){
        return l(f,PR_.OPT);
    },
    PTRACE: function(f){
        return l(f,PTRACE_);
    },
    TYPEID: function(f){
        return l(f,K);
    },
    XATTR: function(f){
        return ["default","XATTR_CREATE","XATTR_REPLACE"][f];
    },
    FNCTL: function(f){
        return l(f,F_);
    },
    SIG: function(f){
        return l(f,S);
    },
    MADV: function(f){
        return l(f,MADV_);
    },
    MCL: function(f){
        return l(f,MCL_);
    },
    MAP: function(f){
        return stringifyBitmap(f,MAP_);
    },
    MS: function(f){
        return l(f,MS_);
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
