import {IStringIndex} from "../utilities/IStringIndex.js";


export const K = {
    P_ALL: [0],
    P_PID: [1],
    P_PGID: [2],
    P_PIDFD: [3]
};
export const FMODE = {
    F_OK: [0],
    X_OK: [1],
    W_OK: [2],
    R_OK: [4]
};

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

export const INOTIFY_FLAGS= {
    IN_NONBLOCK: [O_.O_NONBLOCK],
    IN_CLOEXEC: [O_.O_CLOEXEC]
};

export const INOTIFY_MASK = {
	IN_ACCESS: [0x00000001],
	IN_MODIFY: [0x00000002],
	IN_ATTRIB: [0x00000004],
	IN_CLOSE_WRITE: [0x00000008],
	IN_CLOSE_NOWRITE: [0x00000010],
	IN_CLOSE: [(0x00000008 | 0x00000010)],
	IN_OPEN: [0x00000020],
	IN_MOVED_FROM: [0x00000040],
	IN_MOVED_TO: [0x00000080],
	IN_MOVE: [(0x00000040 | 0x00000080)],
	IN_CREATE: [0x00000100],
	IN_DELETE: [0x00000200],
	IN_DELETE_SELF: [0x00000400],
	IN_MOVE_SELF: [0x00000800],
	IN_ALL_EVENTS: [0x00000fff],
	IN_UNMOUNT: [0x00002000],
	IN_Q_OVERFLOW: [0x00004000],
	IN_IGNORED: [0x00008000],
	IN_ONLYDIR: [0x01000000],
	IN_DONT_FOLLOW: [0x02000000],
	IN_EXCL_UNLINK: [0x04000000],
	IN_MASK_CREATE: [0x10000000],
	IN_MASK_ADD: [0x20000000],
	IN_ISDIR: [0x40000000],
	IN_ONESHOT: [0x80000000]
};

export const RES = {
    RLIMIT_CPU: [0],
    RLIMIT_FSIZE: [1],
    RLIMIT_DATA: [2],
    RLIMIT_STACK: [3],
    RLIMIT_CORE: [4],
    RLIMIT_RSS: [5],
    RLIMIT_NPROC: [6],
    RLIMIT_NOFILE: [7],
    RLIMIT_MEMLOCK: [8],
    RLIMIT_AS: [9],
    RLIMIT_LOCKS: [10],
    RLIMIT_SIGPENDING: [11],
    RLIMIT_MSGQUEUE: [12],
    RLIMIT_NICE: [13],
    RLIMIT_RTPRIO: [14],
    RLIMIT_RTTIME: [15],
    RLIM_NLIMITS: [16],
    RLIM_INFINITY: [(~0) & 0xffffffffffffffff]
};

export const EPOLL_CTL = {
    EPOLL_CTL_ADD: [1],
    EPOLL_CTL_DEL: [2],
    EPOLL_CTL_MOD: [3],
};

export const EPOLL_EV = {
    //EPOLL_CLOEXEC: [O_.O_CLOEXEC],
    EPOLLIN: [0x00000001],
    EPOLLPRI: [0x00000002],
    EPOLLOUT: [0x00000004],
    EPOLLERR: [0x00000008],
    EPOLLHUP: [0x00000010],
    EPOLLNVAL: [0x00000020],
    EPOLLRDNORM: [0x00000040],
    EPOLLRDBAND: [0x00000080],
    EPOLLWRNORM: [0x00000100],
    EPOLLWRBAND: [0x00000200],
    EPOLLMSG: [0x00000400],
    EPOLLRDHUP: [0x00002000],
    EPOLLEXCLUSIVE: [1 << 28],
    EPOLLWAKEUP: [1 << 29],
    EPOLLONESHOT: [1 << 30],
    EPOLLET: [1 << 31],
}
export const SPLICE = {
    SPLICE_F_MOVE: [1],
    SPLICE_F_NONBLOCK: [2],
    SPLICE_F_MORE: [4],
    SPLICE_F_GIFT: [8]
};
export const SYNC_FILE = {
    SYNC_FILE_RANGE_WAIT_BEFORE: [1],
    SYNC_FILE_RANGE_WRITE: [2],
    SYNC_FILE_RANGE_WAIT_AFTER: [4]
};
export const AF_ = {
    AF_UNSPEC: [0],
    AF_UNIX: [1],
    AF_LOCAL: [1],
    AF_INET: [2],
    AF_AX25: [3],
    AF_IPX: [4],
    AF_APPLETALK: [5],
    AF_NETROM: [6],
    AF_BRIDGE: [7],
    AF_ATMPVC: [8],
    AF_X25: [9],
    AF_INET6: [10],
    AF_ROSE: [11],
    AF_DECnet: [12],
    AF_NETBEUI: [13],
    AF_SECURITY: [14],
    AF_KEY: [15],
    AF_NETLINK: [16],
    AF_ROUTE: [16],
    AF_PACKET: [17],
    AF_ASH: [18],
    AF_ECONET: [19],
    AF_ATMSVC: [20],
    AF_RDS: [21],
    AF_SNA: [22],
    AF_IRDA: [23],
    AF_PPPOX: [24],
    AF_WANPIPE: [25],
    AF_LLC: [26],
    AF_CAN: [29],
    AF_TIPC: [30],
    AF_BLUETOOTH: [31],
    AF_IUCV: [32],
    AF_RXRPC: [33],
    AF_ISDN: [34],
    AF_PHONET: [35],
    AF_IEEE802154: [36],
    AF_CAIF: [37],
    AF_ALG: [38],
    AF_NFC: [39],
    AF_VSOCK: [40],
    AF_KCM: [41],
    AF_QIPCRTR: [42],
    AF_MAX: [43]
};
export const SOCK_ = {
    SOCK_STREAM: [1],
    SOCK_DGRAM: [2],
    SOCK_RAW: [3],
    SOCK_RDM: [4],
    SOCK_SEQPACKET: [5],
    SOCK_DCCP: [6],
    SOCK_PACKET: [10],
    SOCK_CLOEXEC: [O_.O_CLOEXEC],
    SOCK_NONBLOCK: [O_.O_NONBLOCK]
};
export const PF_ = {
    PF_UNSPEC: [AF_.AF_UNSPEC[0]],
    PF_UNIX: [AF_.AF_UNIX[0]],
    PF_LOCAL: [AF_.AF_LOCAL[0]],
    PF_INET: [AF_.AF_INET[0]],
    PF_AX25: [AF_.AF_AX25[0]],
    PF_IPX: [AF_.AF_IPX[0]],
    PF_APPLETALK: [AF_.AF_APPLETALK[0]],
    PF_NETROM: [AF_.AF_NETROM[0]],
    PF_BRIDGE: [AF_.AF_BRIDGE[0]],
    PF_ATMPVC: [AF_.AF_ATMPVC[0]],
    PF_X25: [AF_.AF_X25[0]],
    PF_INET6: [AF_.AF_INET6[0]],
    PF_ROSE: [AF_.AF_ROSE[0]],
    PF_DECnet: [AF_.AF_DECnet[0]],
    PF_NETBEUI: [AF_.AF_NETBEUI[0]],
    PF_SECURITY: [AF_.AF_SECURITY[0]],
    PF_KEY: [AF_.AF_KEY[0]],
    PF_NETLINK: [AF_.AF_NETLINK[0]],
    PF_ROUTE: [AF_.AF_ROUTE[0]],
    PF_PACKET: [AF_.AF_PACKET[0]],
    PF_ASH: [AF_.AF_ASH[0]],
    PF_ECONET: [AF_.AF_ECONET[0]],
    PF_ATMSVC: [AF_.AF_ATMSVC[0]],
    PF_RDS: [AF_.AF_RDS[0]],
    PF_SNA: [AF_.AF_SNA[0]],
    PF_IRDA: [AF_.AF_IRDA[0]],
    PF_PPPOX: [AF_.AF_PPPOX[0]],
    PF_WANPIPE: [AF_.AF_WANPIPE[0]],
    PF_LLC: [AF_.AF_LLC[0]],
    PF_CAN: [AF_.AF_CAN[0]],
    PF_TIPC: [AF_.AF_TIPC[0]],
    PF_BLUETOOTH: [AF_.AF_BLUETOOTH[0]],
    PF_IUCV: [AF_.AF_IUCV[0]],
    PF_RXRPC: [AF_.AF_RXRPC[0]],
    PF_ISDN: [AF_.AF_ISDN[0]],
    PF_PHONET: [AF_.AF_PHONET[0]],
    PF_IEEE802154: [AF_.AF_IEEE802154[0]],
    PF_CAIF: [AF_.AF_CAIF[0]],
    PF_ALG: [AF_.AF_ALG[0]],
    PF_NFC: [AF_.AF_NFC[0]],
    PF_VSOCK: [AF_.AF_VSOCK[0]],
    PF_KCM: [AF_.AF_KCM[0]],
    PF_QIPCRTR: [AF_.AF_QIPCRTR[0]],
    PF_MAX: [AF_.AF_MAX[0]]
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
export const MLOCK = {
    MLOCK_ONFAULT: [1]
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
    DUMPABLE: {
        SUID_DUMP_DISABLE: 0,
        SUID_DUMP_USER: 1
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



/*S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)*/
export const S_ = {
    S_IFMT: [0o0170000],
    S_IFSOCK: [0o140000],
    S_IFLNK: [0o120000],
    S_IFREG: [0o100000],
    S_IFBLK: [0o060000],
    S_IFDIR: [0o040000],
    S_IFCHR: [0o020000],
    S_IFIFO: [0o010000],
    S_ISUID: [0o004000],
    S_ISGID: [0o002000],
    S_ISVTX: [0o001000],
    S_IRWXU: [0o0700],
    S_IRUSR: [0o0400],
    S_IWUSR: [0o0200],
    S_IXUSR: [0o0100],
    S_IRWXG: [0o0070],
    S_IRGRP: [0o0040],
    S_IWGRP: [0o0020],
    S_IXGRP: [0o0010],
    S_IRWXO: [0o0007],
    S_IROTH: [0o0004],
    S_IWOTH: [0o0002],
    S_IXOTH: [0o0001]
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
export const CLOCK = {
    CLOCK_REALTIME: [0],
    CLOCK_MONOTONIC: [1],
    CLOCK_PROCESS_CPUTIME_ID: [2],
    CLOCK_THREAD_CPUTIME_ID: [3],
    CLOCK_MONOTONIC_RAW     : [4],
    CLOCK_REALTIME_COARSE   : [5],
    CLOCK_MONOTONIC_COARSE  : [6],
    CLOCK_BOOTTIME          : [7],
    CLOCK_REALTIME_ALARM    : [8],
    CLOCK_BOOTTIME_ALARM    : [9],
    CLOCK_SGI_CYCLE        : [10],
    CLOCK_TAI              : [11]
} ;

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
export const ITIMER = {
    ITIMER_REAL:    [0],
    ITIMER_VIRTUAL: [1],
    TIMER_PROF:    [2]
}
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
export const PERSO = {
    UNAME26: [0x0020000],
    ADDR_NO_RANDOMIZE: [0x0040000],
    FDPIC_FUNCPTRS: [0x0080000],
    MMAP_PAGE_ZERO: [0x0100000],
    ADDR_COMPAT_LAYOUT: [0x0200000],
    READ_IMPLIES_EXEC: [0x0400000],
    ADDR_LIMIT_32BIT: [0x0800000],
    SHORT_INODE: [0x1000000],
    WHOLE_SECONDS: [0x2000000],
    STICKY_TIMEOUTS: [0x4000000],
    ADDR_LIMIT_3GB: [0x8000000]
};
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

export const FUTEX:any = {
    FUTEX_WAIT: [0],
    FUTEX_WAKE: [1],
    FUTEX_FD: [2],
    FUTEX_REQUEUE: [3],
    FUTEX_CMP_REQUEUE: [4],
    FUTEX_WAKE_OP: [5],
    FUTEX_LOCK_PI: [6],
    FUTEX_UNLOCK_PI: [7],
    FUTEX_TRYLOCK_PI: [8],
    FUTEX_WAIT_BITSET: [9],
    FUTEX_WAKE_BITSET: [10],
    FUTEX_WAIT_REQUEUE_PI: [11],
    FUTEX_CMP_REQUEUE_PI: [12],
    FUTEX_LOCK_PI2: [13],
    FUTEX_PRIVATE_FLAG: [128],
    FUTEX_CLOCK_REALTIME: [256]
};

FUTEX.FUTEX_CMD_MASK = [~(FUTEX.FUTEX_PRIVATE_FLAG[0] | FUTEX.FUTEX_CLOCK_REALTIME[0] )];
FUTEX.FUTEX_WAIT_PRIVATE = [(FUTEX.FUTEX_WAIT[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_WAKE_PRIVATE = [(FUTEX.FUTEX_WAKE[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_REQUEUE_PRIVATE = [(FUTEX.FUTEX_REQUEUE[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_CMP_REQUEUE_PRIVATE = [(FUTEX.FUTEX_CMP_REQUEUE[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_WAKE_OP_PRIVATE = [(FUTEX.FUTEX_WAKE_OP[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_LOCK_PI_PRIVATE = [(FUTEX.FUTEX_LOCK_PI[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_LOCK_PI2_PRIVATE = [(FUTEX.FUTEX_LOCK_PI2[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_UNLOCK_PI_PRIVATE = [(FUTEX.FUTEX_UNLOCK_PI[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_TRYLOCK_PI_PRIVATE = [(FUTEX.FUTEX_TRYLOCK_PI[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_WAIT_BITSET_PRIVATE = [(FUTEX.FUTEX_WAIT_BITSET[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_WAKE_BITSET_PRIVATE = [(FUTEX.FUTEX_WAKE_BITSET[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_WAIT_REQUEUE_PI_PRIVATE = [(FUTEX.FUTEX_WAIT_REQUEUE_PI[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
FUTEX.FUTEX_CMP_REQUEUE_PI_PRIVATE = [(FUTEX.FUTEX_CMP_REQUEUE_PI[0] | FUTEX.FUTEX_PRIVATE_FLAG[0] )];
export const SIG_FLAG = {
    SIG_BLOCK:     [0],
    SIG_UNBLOCK:   [1],
    SIG_SETMASK:   [2]
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

export const MOUNT = {
	MS_RDONLY: [1], /* Mount read-only */
	MS_NOSUID: [2], /* Ignore suid and sgid bits */
	MS_NODEV: [4], /* Disallow access to device special files */
	MS_NOEXEC: [8], /* Disallow program execution */
	MS_SYNCHRONOUS: [16], /* Writes are synced at once */
	MS_REMOUNT: [32], /* Alter flags of a mounted FS */
	MS_MANDLOCK: [64], /* Allow mandatory locks on an FS */
	MS_DIRSYNC: [128], /* Directory modifications are synchronous */
	MS_NOSYMFOLLOW: [256], /* Do not follow symlinks */
	MS_NOATIME: [1024], /* Do not update access times. */
	MS_NODIRATIME: [2048], /* Do not update directory access times */
    MS_BIND:		[4096],
    MS_MOVE:		[8192],
    MS_REC:		[16384],
	// MS_VERBOSE: [32768], /* War is peace. Verbosity is silence. MS_VERBOSE is deprecated. */
    MS_SILENT:	[32768],
	MS_POSIXACL: [(1<<16)], /* VFS does not apply the umask */
	MS_UNBINDABLE: [(1<<17)], /* change to unbindable */
	MS_PRIVATE: [(1<<18)], /* change to private */
	MS_SLAVE: [(1<<19)], /* change to slave */
	MS_SHARED: [(1<<20)], /* change to shared */
	MS_RELATIME: [(1<<21)], /* Update atime relative to mtime/ctime. */
	MS_KERNMOUNT: [(1<<22)], /* this is a kern_mount call */
	MS_I_VERSION: [(1<<23)], /* Update inode I_version field */
	MS_STRICTATIME: [(1<<24)], /* Always perform atime updates */
	MS_LAZYTIME: [(1<<25)] /* Update the on-disk [acm]times lazily */
}
export const MEMBARRIER_FLAG = {
    MEMBARRIER_CMD_FLAG_CPU: [(1 << 0)]
}
export const MEMBARRIER_CMD = {
    MEMBARRIER_CMD_QUERY: [0],
    MEMBARRIER_CMD_GLOBAL: [(1 << 0)],
    MEMBARRIER_CMD_GLOBAL_EXPEDITED: [(1 << 1)],
    MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: [(1 << 2)],
    MEMBARRIER_CMD_PRIVATE_EXPEDITED: [(1 << 3)],
    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: [(1 << 4)],
    MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: [(1 << 5)],
    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: [(1 << 6)],
    MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: [(1 << 7)],
    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: [(1 << 8)],
    MEMBARRIER_CMD_SHARED: [(1 << 0)] // MEMBARRIER_CMD_GLOBAL
}
export const IOPRIO_WHO =  {
    NULL: [0],
    IOPRIO_WHO_PROCESS: [1],
    IOPRIO_WHO_PGRP: [2],
    IOPRIO_WHO_USER: [3],
};

export const IOPRIO_CLASS =  {
    IOPRIO_CLASS_NONE: [0],
    IOPRIO_CLASS_RT: [1],
    IOPRIO_CLASS_BE: [2],
    IOPRIO_CLASS_IDLE: [3],
};


export const SEEK_ = {
    SEEK_SET: [0],
    SEEK_CUR: [1],
    SEEK_END: [2],
    SEEK_DATA: [3],
    SEEK_HOLE: [4]
};

export const SCHED_ = {
    SCHED_NORMAL: [0],
    SCHED_FIFO: [1],
    SCHED_RR: [2],
    SCHED_BATCH: [3],
    SCHED_IDLE: [5],
    SCHED_DEADLINE: [6],
    SCHED_RESET_ON_FORK: [0x40000000],
    SCHED_FLAG_RESET_ON_FORK: [0x01],
    SCHED_FLAG_RECLAIM: [0x02],
    SCHED_FLAG_DL_OVERRUN: [0x04],
    SCHED_FLAG_KEEP_POLICY: [0x08],
    SCHED_FLAG_KEEP_PARAMS: [0x10],
    SCHED_FLAG_UTIL_CLAMP_MIN: [0x20],
    SCHED_FLAG_UTIL_CLAMP_MAX: [0x40]
};
export const TIMER = {
    TFD_TIMER_ABSTIME: [(1 << 0)],
    TFD_TIMER_CANCEL_ON_SET: [(1 << 1)]
};
export const RWF = {
    RWF_HIPRI: [0x00000001],
    RWF_DSYNC: [0x00000002],
    RWF_SYNC: [0x00000004],
    RWF_NOWAIT: [0x00000008],
    RWF_APPEND: [0x00000010]
};
export const SECCOMP = {
    SECCOMP_SET_MODE_STRICT: [0],
    SECCOMP_SET_MODE_FILTER: [1],
    SECCOMP_GET_ACTION_AVAIL: [2],
    SECCOMP_GET_NOTIF_SIZES: [3]
};
export const LOCK = {
	LOCK_SH: [1],
	LOCK_EX: [2],
	LOCK_NB: [4],
	LOCK_UN: [8],
	LOCK_MAND: [32],
	LOCK_READ: [64],
	LOCK_WRITE: [128],
	LOCK_RW: [192]
};
export const FALLOC = {
	FALLOC_FL_KEEP_SIZE: [0x01],
	FALLOC_FL_PUNCH_HOLE: [0x02],
	FALLOC_FL_NO_HIDE_STALE: [0x04],
	FALLOC_FL_COLLAPSE_RANGE: [0x08],
	FALLOC_FL_ZERO_RANGE: [0x10],
	FALLOC_FL_INSERT_RANGE: [0x20],
	FALLOC_FL_UNSHARE_RANGE: [0x40],
};
export const PKEY = {
    PKEY_DISABLE_ACCESS:	[0x1],
    PKEY_DISABLE_WRITE:	[0x2]
};
export const CLONE = {
    CLONE_NEWTIME: [0x00000080],
    CLONE_VM: [0x00000100],
    CLONE_FS: [0x00000200],
    CLONE_FILES: [0x00000400],
    CLONE_SIGHAND: [0x00000800],
    CLONE_PIDFD: [0x00001000],
    CLONE_PTRACE: [0x00002000],
    CLONE_VFORK: [0x00004000],
    CLONE_PARENT: [0x00008000],
    CLONE_THREAD: [0x00010000],
    CLONE_NEWNS: [0x00020000],
    CLONE_SYSVSEM: [0x00040000],
    CLONE_SETTLS: [0x00080000],
    CLONE_PARENT_SETTID: [0x00100000],
    CLONE_CHILD_CLEARTID: [0x00200000],
    CLONE_DETACHED: [0x00400000],
    CLONE_UNTRACED: [0x00800000],
    CLONE_CHILD_SETTID: [0x01000000],
    CLONE_NEWCGROUP: [0x02000000],
    CLONE_NEWUTS: [0x04000000],
    CLONE_NEWIPC: [0x08000000],
    CLONE_NEWUSER: [0x10000000],
    CLONE_NEWPID: [0x20000000],
    CLONE_NEWNET: [0x40000000],
    CLONE_IO: [0x80000000]
}
export const RUSAGE = {
    RUSAGE_SELF:		[0],
    RUSAGE_CHILDREN:		[-1]
}
export const IPC = {
    IPC_RMID: [0], /* remove resource */
    IPC_SET: [1], /* set ipc_perm options */
    IPC_STAT: [2], /* get ipc_perm options */
    IPC_INFO: [3], /* see ipcs */
    IPC_CREAT:  [0o0001000],   /* create if key is nonexistent */
    IPC_EXCL:   [0o0002000],   /* fail if key exists */
    IPC_NOWAIT: [0o0004000]   /* return error on wait */
}
export const MSG = {
    MSG_STAT: [11],
    MSG_INFO: [12],
    MSG_STAT_ANY: [13],
    MSG_NOERROR: [0o010000],
    MSG_EXCEPT: [0o020000],
    MSG_COPY: [0o040000]
}
//
export const E:IStringIndex = {
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
function stringifyBitmapArr(val:number, flags:any):string{
    let s = "";
    for(const f in flags){
        if((val & flags[f][0]) == flags[f][0]) s += (s.length>0?" | ":"")+f;
    }

    return s;
}

export const I = {
    KILL_FROM: function(ctx:any){
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
export const ERR:IStringIndex = {};

for(const k in E){
    E[k].push(k);
    ERR[k] = E[k][0];
}

function l( val:number, list:any){
    for(const k in list) if(val == list[k][0]) return k;
    return val;
}

export const X = {
    RANGE: function(p:NativePointerValue){
        try{
            const m = Process.getModuleByAddress(p);
            return `${p} (${m!=null ? m.name : 'null'})`;
        }catch(e){
            return `${p}`;
        }
    },
    LINKAT: function(f:number){
        if(f == AT_.AT_SYMLINK_FOLLOW[0] )
            return "AT_SYMLINK_FOLLOW";
        else
            return  0; // no flag
    },
    MLOCK: function(f:number){
        if(f == MLOCK.MLOCK_ONFAULT[0] )
            return "MLOCK_ONFAULT";
        else
            return  0; // no flag
    },
    PKEY_ACL: function(f:number){
        return l(f,PKEY);
    },
    RUSAGE: function(f:number){
        return l(f, RES);
    },
    RES: function(f:number){
        return l(f,RES);
    },
    RWF: function(f:number){
        return l(f,RWF);
    },
    SECCOMP: function(f:number){
        return l(f,SECCOMP);
    },
    SECCOMP_FLAGS: function(f:number,cmd:any){
        return f;
        /*
        switch(cmd){
            case SECCOMP.SECCOMP_SET_MODE_STRICT:
                return l(f,SECCOMP);
                break;
            case SECCOMP.SECCOMP_SET_MODE_FILTER:
                return l(f,SECCOMP);
                break;
            case SECCOMP.SECCOMP_GET_ACTION_AVAIL:
                return f;
            case SECCOMP.SECCOMP_GET_NOTIF_SIZES:
                return f;
            default:
                return f;
        }
        */
    },
    MEMBARRIER_CMD: function(f:number){
        return l(f,MEMBARRIER_CMD);
    },
    MEMBARRIER_FLAG: function(f:number){
        return l(f,MEMBARRIER_FLAG);
    },
    ACCESS_FLAGS: function(f:number){
        return stringifyBitmapArr(f, {
            AT_SYMLINK_NOFOLLOW: [0x100],
            AT_NO_AUTOMOUNT: [0x800],
            AT_EMPTY_PATH: [0x1000]
        });
    },
    EPOLL_EV: function(f:number){
        return stringifyBitmapArr(f, EPOLL_EV);
    },
    SPLICE: function(f:number){
        return stringifyBitmapArr(f, SPLICE);
    },
    ITIMER: function(f:number){
        return stringifyBitmapArr(f, ITIMER);
    },
    SYNC_FILE: function(f:number){
        return stringifyBitmapArr(f, SYNC_FILE);
    },
    EPOLL_CTL: function(f:number){
        return stringifyBitmapArr(f, EPOLL_CTL);
    },
    EPOLL_FLAG: function(f:number){
        return stringifyBitmapArr(f, {
            EPOLL_CLOEXEC: [O_.O_CLOEXEC]
        });
    },
    PRCTL_OPT: function(f:number){
        return l(f,PR_.OPT);
    },
    CLONE: function(f:number){
        return stringifyBitmapArr(f,CLONE);
    },
    CLK: function(f:number){
        return l(f,CLOCK);
    },
    SCHED: function(f:number){
        return l(f,SCHED_);
    },
    SEEK: function(f:number){
        return l(f,SEEK_);
    },
    INOTIFY_FLAGS: function(f:number){
        return l(f,INOTIFY_FLAGS);
    },
    INOTIFY_MASK: function(f:number){
        return l(f,INOTIFY_MASK);
    },
    FUTEX_OPE: function(f:number){
        return l(f,FUTEX);
    },
    PTRACE: function(f:number){
        return l(f,PTRACE_);
    },
    NODMODE: function(f:number){
        // todo parse dev
        return stringifyBitmapArr(f, {
            S_IFREG: S_.S_IFREG,
            S_IFCHR: S_.S_IFCHR,
            S_IFBLK: S_.S_IFBLK,
            S_IFIFO: S_.S_IFIFO,
            S_IFSOCK: S_.S_IFSOCK
        });
    },
    FLOCK: function(f:number){
        return l(f,LOCK);
    },
    FALLOC: function(f:number){
        return l(f,FALLOC);
    },
    IOPRIO_WHICH: function(f:number, cmd:any){
        return l(f, IOPRIO_WHO);
        /*console.error(f, cmd);
        switch(f){
            case IOPRIO_WHO.IOPRIO_WHO_PROCESS:
            case IOPRIO_WHO.IOPRIO_WHO_PGRP:
            case IOPRIO_WHO.IOPRIO_WHO_USER:
            default:
                return f;
                break;
        }*/
    },
    PERSO: function(f:number){
        return l(f,PERSO);
    },
    TYPEID: function(f:number){
        return l(f,K);
    },
    XATTR: function(f:number){
        return ["default","XATTR_CREATE","XATTR_REPLACE"][f];
    },
    UNLINK: function(f:number){
        return l(f,{AT_REMOVEDIR:AT_.AT_REMOVEDIR});
    },
    PIPE_FLAG: (f:number)=>{
        return stringifyBitmapArr(f,{O_NONBLOCK:O_.O_NONBLOCK,O_CLOEXEC :O_.O_CLOEXEC});
    },
    SOCKF: (f:number)=>{
        return stringifyBitmapArr(f,{SOCK_NONBLOCK:O_.O_NONBLOCK,SOCK_CLOEXEC :O_.O_CLOEXEC});
    },
    SFD: (f:number)=>{
        return stringifyBitmapArr(f,{SFD_NONBLOCK:O_.O_NONBLOCK,SFD_CLOEXEC :O_.O_CLOEXEC});
    },
    TFD: (f:number)=>{
        return stringifyBitmapArr(f,{TFD_NONBLOCK:O_.O_NONBLOCK,TFD_CLOEXEC :O_.O_CLOEXEC});
    },
    TIMER: (f:number)=>{
        return stringifyBitmapArr(f,TIMER);
    },
    FNCTL: function(f:number){
        return l(f,F_);
    },
    FCNTL_RET: function(f:number, cmd:any){
        switch (cmd) {
            case F_.F_GETFL:
                return X.O_MODE(f);
                break;
            default:
                return f;
        }
    },
    FCNTL_ARGS: function(f:number, cmd:any){
        switch (cmd) {
            case F_.F_SETFL:
                return X.O_MODE(f);
                break;
            default:
                return f;
        }
    },
    MSGF: function(f:number){
        return stringifyBitmapArr(f,{
            IPC_NOWAIT: [IPC.IPC_NOWAIT],
            MSG_EXCEPT : [MSG.MSG_EXCEPT],
            MSG_NOERROR: [MSG.MSG_NOERROR],
        });
    },
    MSGCTL: function(f:number){
        return l(f,{
            IPC_STAT: [IPC.IPC_NOWAIT],
            IPC_SET : [IPC.IPC_SET],
            IPC_RMID: [IPC.IPC_RMID],
            IPC_INFO: [IPC.IPC_INFO],
            MSG_INFO: [MSG.MSG_INFO],
            MSG_STAT: [MSG.MSG_STAT],
            MSG_STAT_ANY: [MSG.MSG_STAT_ANY]
        });
    },
    DEL_KEXT: function(f:number){
        return stringifyBitmapArr(f,{O_NONBLOCK:O_.O_NONBLOCK,O_TRUNC :O_.O_TRUNC});
    },
    SIG_FLAGS: function(f:number){
        return l(f,SIG_FLAG);
    },
    SIG: function(f:number){
        return l(f,S);
    },
    PF: function(f:number){
        return l(f,PF_);
    },
    SOCK: function(f:number){
        return stringifyBitmapArr(f,SOCK_);
    },
    MOUNT_FLAG: function(f:number){
        return stringifyBitmapArr(f,MOUNT);
    },
    MADV: function(f:number){
        return l(f,MADV_);
    },
    MCL: function(f:number){
        return l(f,MCL_);
    },
    MAP: function(f:number){
        return stringifyBitmapArr(f,MAP_);
    },
    MS: function(f:number){
        return l(f,MS_);
    },
    ERR: function(f:number){
        for(const k in E) if(f == E[k][0]) return k+" /* "+E[k][1]+" */";
        return null;
    },
    ATTR: function(f:number){
        return f;
    },
    UMASK: function(f:number){
        return stringifyBitmapArr(f,S_);
    },
    O_FLAG: function(f:number){
        return stringifyBitmap(f,O_);
    },
    O_MODE: function(f:number){
        return stringifyBitmap(f,O_);
    },
    F_MODE: function(f:number){
        return stringifyBitmapArr(f,FMODE);
    },
    UMOUNT: function(f:number){
        return stringifyBitmapArr(f,MNT_);
    },
    MFD: function(f:number){
        return stringifyBitmapArr(f,MFD);
    },
    MPROT: function(f:number){
        if(f == PROT_NONE)
            return "PROT_NONE";

        return stringifyBitmap(f,PROT_);
    },
}
