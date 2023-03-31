
// arguments template
import {L, SyscallOutMap, SyscallSignature, T} from "../common/Types.js";
import * as DEF from "../kernelapi/MacosX64Flags.js";
import {TypedData, TypedDataMap} from "../common/TypedData.js";
import {constants} from "os";
import EACCES = module


const E = DEF.E;
const X = DEF.X;
const _ = TypedData.from;


// internal structs are always parsed
export const IDSTRUCTS = {};


const A:TypedDataMap = {
    // verified
    CONST_PATH: _({ t:T.STRING, n:"path", l:L.PATH, c:true }), // A.CONST_PATH  {t:T.STRING, n:"path", l:L.PATH, c:true}),
    LEN: _({t:T.LONG, n:"length", l:L.SIZE}),
    FD: _({t:T.UINT32, n:"fd", l:L.FD}),
    UID: _({t:T.UINT32, n:"user", l:L.UID }),
    GID: _({t:T.UINT32, n:"group", l:L.GID }),
    SOCKFD: _({t:T.INT32, n:"sockfd", l:L.SOCKFD}),
    SOCKLEN: _({t:T.UINT32, n:"socklen" }),
    SOCKADDR: _( {t:T.POINTER64, n:"*addr", l:L.DSTRUCT, f:"sock_addr"}),
    OUTPUT_BUFFER_LEN: _({t:T.INT32, n:"size", l:L.SIZE}),
    OUTPUT_CHAR_BUFFER: _({t:T.POINTER64, n:"buf", l:L.OUTPUT_BUFFER}),
    ADDR: _({t:T.POINTER64, n:"addr", l:L.VADDR, f:X.RANGE}),

    RUSAGE: _({t:T.POINTER64, n:"*rusage", l:L.DSTRUCT, f:"rusage"}),
    COPYFILE_STATE: _({t:T.POINTER64, n:"state", l:L.DSTRUCT, f:"copyfile_state_t"}),

    AIOCBP: _({ t:T.POINTER64, n:"*aiocbp", l:L.DSTRUCT, f:"aiocbp" }),

    // === copied from linux/x64
    DFD: _({t: T.INT32, n:"dfd", l:L.DFD}),
    OLD_DFD: _({t: T.INT32, n:"old_dfd", l:L.DFD}),
    NEW_DFD: _({t: T.INT32, n:"new_dfd", l:L.DFD}),
    FD_SET: _({t:T.POINTER64, n:"fd_set*", l:L.BUFFER, f:"FD" }),
    EPFD: _({t:T.UINT32, n:"epfd", l:L.EPFD}),
    AIO: _({t:T.ULONG, n:"aio_context_t ctx_id"}),
    LFD: _({t:T.ULONG, n:"fd", l:L.FD}),
    CONST_NAME: _({t:T.STRING, n:"name", c:true}),
    STR: _({t:T.STRING, n:"char*"}),
    OLD_NAME: _({t:T.CHAR_BUFFER, n:"old_name", c:true}),
    NEW_NAME: _({t:T.CHAR_BUFFER, n:"new_name", c:true}),
    CONST_FNAME: _({t:T.STRING, n:"filename", c:true}),
    FNAME: _({t:T.STRING, n:"filename"}),
    SIZE: _({t:T.UINT32, n:"size", l:L.SIZE}),
    SSIZE: _({t:T.INT32, n:"size", l:L.SIZE}),
    OFFSET: _({t:T.UINT32, n:"offset", l:L.SIZE}),
    LOFFSET: _({t:T.ULONG, n:"offset", l:L.SIZE}),
    SIGNED_LEN: _({t:T.LONG, n:"length", l:L.SIZE}),
    XATTR: _({t:T.INT32, n:"flags", l:L.FLAG, f:X.XATTR }),
    XATTR_LIST: _({t:T.CHAR_BUFFER, n:"list", l:L.XATTR_LIST, r:2}),
    PID: _({t:T.INT32, n:"pid", l:L.PID }),
    SCHED_POLICY: _({t:T.UINT32, n:"policy", l:L.FLAG, f:X.SCHED}),
    SIG: _({t:T.INT32, n:"sig", l:L.FLAG, f:X.SIG   }),
    TID: _({t:T.INT32, n:"thread" }),
    CALLER_TID: _({t:T.INT32, n:"caller_tid" }),
    PTR: _({t:T.POINTER64, n:"value"}),
    START_ADDR: _({t:T.POINTER64, n:"start_addr", l:L.VADDR, f:X.RANGE}),
    CONST_PTR: _({t:T.POINTER64, n:"value", c:true}),
    MPROT: _({t:T.INT32, n:"prot", l:L.FLAG, f:X.MPROT}),
    FMODE: _({t:T.INT32, n:"mode", l:L.FLAG, f:X.F_MODE}),
    CLKID: _({t:T.INT32, n:"clockid", l:L.FLAG, f:X.CLK}),
    WD: _({t:T.INT32, n:"wd", l:L.WD}),
    IOPRIO_WHICH: _({ t:T.INT32, n:"which", l:L.FLAG, r:"x1", f:X.IOPRIO_WHICH }),
    ACCESS_FLAGS: _({t:T.INT32, n:"flag", l:L.FLAG, f:X.ACCESS_FLAGS}),
    PKEY: _({ t:T.INT32, n:"pkey", l:L.PKEY}),
    RWF: _({t:T.INT32, n:"rwf", l:L.FLAG, f:X.RWF}),
    SIGMASK: _({t:T.POINTER64, n:"sigmask", l:L.BUFFER}),
    TIMER: _({ t:T.INT32, n:"which", l:L.FLAG, f:X.TIMER}),
    TIMER_PTR: _({ t:T.POINTER64, n:"timer_id*", l:L.TIMER}),
    PERSO: _({ t:T.UINT32, n:"personna", l:L.FLAG, f:X.PERSO}),
    RES: _({ t:T.UINT32, n:"resource", l:L.FLAG, f:X.RES}),
    OFLAGS: _({t:T.UINT32, n:"flags", l:L.FLAG, f:X.O_MODE}),
    OMODE: _({t:T.UINT32, n:"mode", l:L.FLAG, f:X.UMASK}),
    MQD: _({ t:T.INT32, n:"mod_t mqdes", l:L.MQDES}),
    MQID: _({ t:T.INT32, n:"msqid" }),
    SEMID: _({ t:T.INT32, n:"semid" }),
    EPEV: _({t:T.POINTER64, n:"struct epoll_event *event", l:L.FLAG, f:X.EPOLL_EV}),
    COUNT: _({t:T.UINT32, n:"count", l:L.SIZE}),

    POLLFD: _({ t:T.INT32, n:"*pollfd", l:L.DSTRUCT, f:"pollfd" }),
    KERNEL_TIMESPEC: _({t:T.POINTER64, n:"*__kernel_timespec", l:L.DSTRUCT, f:"__kernel_timespec"} ),
    CONST_KERNEL_TIMESPEC: _({t:T.POINTER64, n:"*__kernel_timespec", l:L.DSTRUCT, f:"__kernel_timespec", c:true} ),
    IOVEC: _({t:T.POINTER64, n:"*iovec", l:L.DSTRUCT, f:"iovec", c:true}),
    IOCB: _({t:T.POINTER64, n:"*iocb", l:L.DSTRUCT, f:"iocb"} ),
    IOEV: _({t:T.POINTER64, n:"*io_event", l:L.DSTRUCT, f:"io_event"} ),
    SCHED_PARAM: _({t:T.POINTER64, n:"*sched_param", l:L.DSTRUCT, f:"sched_param"}),
    SCHED_ATTR: _({t:T.POINTER64, n:"*attr", l:L.DSTRUCT, f:"sched_attr"} ),
    STATBUF: _({t:T.POINTER64, n:"*statbuf", l:L.DSTRUCT, f:"__old_kernel_stat"}),
    ITIMERVAL: _({t:T.POINTER64, n:"*itimerval", l:L.DSTRUCT, f:"itimerval"}),
    ITIMERSPEC: _({t:T.POINTER64, n:"*itimerspec", l:L.DSTRUCT, f:"__kernel_itimerspec"}),
    SIGINFO: _({t:T.POINTER64, n:"*siginfo", l:L.DSTRUCT, f:"siginfo"}),
    TMS: _({t:T.POINTER64, n:"*tbuf", l:L.DSTRUCT, f:"tms"}),
    RLIMIT: _({t:T.POINTER64, n:"**rlim", l:L.DSTRUCT, f:"rlimit"}),
    ROBUST_LH: _({t:T.POINTER64, n:"*head", l:L.DSTRUCT, f:"robust_list_head"}),
    KEXSEG: _({t:T.POINTER64, n:"*segments", l:L.DSTRUCT, f:"kexec_segment"}),
    SIGEVENT: _({t:T.POINTER64, n:"*notification", l:L.DSTRUCT, f:"sigevent"}),
    SIGALSTACK: _({t:T.POINTER64, n:"*uss", l:L.DSTRUCT, f:"sigaltstack"}),
    SIGACTION: _({t:T.POINTER64, n:"*sigaction", l:L.DSTRUCT, f:"sigaction"}),
    TIMEVAL: _({t:T.POINTER64, n:"*timeval", l:L.DSTRUCT, f:"timeval"}),
    TIMEZONE: _({t:T.POINTER64, n:"*timezone", l:L.DSTRUCT, f:"timezone"}),
    KTIMEX: _({t:T.POINTER64, n:"*txc", l:L.DSTRUCT, f:"__kernel_timex"}),
    SYSINFO: _({t:T.POINTER64, n:"*sysinfo", l:L.DSTRUCT, f:"sysinfo"}),
    MQ_ATTR: _({t:T.POINTER64, n:"*mq_attr", l:L.DSTRUCT, f:"mq_attr"}),
    MSGBUFF: _( {t:T.POINTER64, n:"*msgbuf", l:L.DSTRUCT, f:"msgbuf"} ),
    CAP_USR_HEADER: _({t:T.POINTER64, n:"*cap_header", l:L.DSTRUCT, f:"cap_user_header_t"}),
    CAP_USR_DATA: _({t:T.POINTER64, n:"*cap_data", l:L.DSTRUCT, f:"cap_user_data_t"}),
    GPU_CACHE: _({t:T.POINTER64, n:"*getcpu_cache", l:L.DSTRUCT, f:"getcpu_cache"}),
    SEMBUF: _({t:T.POINTER64, n:"*sops", l:L.DSTRUCT, f:"sembuf"}),
    FILE_HANDLE: _({t:T.POINTER64, n:"*handle", l:L.DSTRUCT, f:"file_handle"}),
    MSGBUF: _({t:T.POINTER64, n:"*msgb", l:L.DSTRUCT, f:"msgbuf"} ),
    USR_MSGHDR: _({t:T.POINTER64, n:"*msg", l:L.DSTRUCT, f:"user_msghdr"} ),
    RLIMIT64: _( {t:T.POINTER64, n:"*rlim", l:L.DSTRUCT, f:"rlimit64"}),
    SHMIDDS: _( {t:T.POINTER64, n:"*buf", l:L.DSTRUCT, f:"shmid_ds"}),
    MMSGHDR: _( {t:T.POINTER64, n:"*msg", l:L.DSTRUCT, f:"mmsghdr"}),
    PERFEVTATTR: _( {t:T.POINTER64, n:"*attr_uptr", l:L.DSTRUCT, f:"perf_event_attr"}),
    STATX: _( {t:T.POINTER64, n:"*buffer", l:L.DSTRUCT, f:"statx"})
}

A.SIGMASK.update({ f:A.SIG, len:16 });

const RET:SyscallOutMap = {
    INFO: {t:T.INT32, e:[E.EAGAIN,E.EINVAL,E.EPERM]},
    ACCESS: {t:T.INT32, e:[E.EACCES, E.EFAULT, E.EINVAL, E.ELOOP, E.ENAMETOOLONG, E.ENOENT, E.ENOMEM, E.ENOTDIR, E.EOVERFLOW, E.EIO, E.ETXTBSY, E.EROFS]},
    STAT: {t:T.INT32, e:[E.EACCES, E.EBADF, E.EFAULT, E.EINVAL, E.ELOOP, E.ENAMETOOLONG, E.ENOENT, E.ENOMEM, E.ENOTDIR, E.EOVERFLOW]},
    LINK: {t:T.INT32, e:[E.EACCES,E.EEXIST, E.EFAULT, E.EIO, E.ELOOP, E.EMLINK, E.ENAMETOOLONG, E.ENOENT, E.ENOMEM, E.ENOSPC,E.ENOTDIR, E.EPERM,E.EROFS,E.EXDEV] },
    OPEN: {t:T.INT32, e:[E.EACCES,E.EEXIST, E.EFAULT, E.ENODEV, E.ENOENT, E.ENOMEM, E.ENOSPC, E.ENOTDIR, E.ENXIO, E.EPERM, E.EROFS, E.ETXTBSY,  E.EFBIG, E.EINTR, E.EISDIR, E.ELOOP, E.ENAMETOOLONG, E.EMFILE,E.ENFILE,E.ENOMEM]},
}

RET.VADDR = {t:T.INT32, n:'addr', l:L.VADDR, e:[ E.EACCES, E.EAGAIN, E.EBADF, E.EINVAL, E.ENFILE, E.ENODEV, E.ENOMEM, E.ETXTBSY]};
RET.SET_XATTR = {t:T.INT32, e:RET.STAT.e.concat([E.EDQUOT, E.EEXIST, E.ENODATA, E.ENOSPC, E.ENOTSUP, E.EPERM, E.ERANGE]) };
RET.GET_XATTR = {t:T.INT32, e:RET.STAT.e.concat([E.E2BIG, E.ENODATA, E.ENOTSUP, E.ERANGE]) };
RET.LS_XATTR = {t:T.INT32, e:RET.STAT.e.concat([E.E2BIG, E.ENOTSUP, E.ERANGE]) };
RET.RM_XATTR = {t:T.INT32, e:RET.STAT.e.concat([E.ENOTSUP, E.ERANGE]) };
RET.OPENAT = {t:T.INT32, n:'FD', l:L.FD, r:1, e:RET.OPEN.e.concat([E.EBADF, E.ENOTDIR]) };
RET.LINKAT = {t:T.INT32, e:RET.LINK.e.concat([E.EBADF, E.ENOTDIR]) };
RET.IO = {t:T.INT32, e:RET.INFO.e.concat([E.EBADF, E.EFAULT, E.ENOSYS]) };


export const SYSC:SyscallSignature[] = [
    [0, "nosys", 0, [] ], // [extra=indirect syscall]
    [1, "exit", 1,  [{ t:T.INT32, n:"status" }] , null],
    [2, "fork", 2,  [] , A.PID.asReturn()],
    [3, "read", 3,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.LEN.copy("nbyte")] , A.OUTPUT_BUFFER_LEN.asReturn()],
    [4, "write", 4,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.OUTPUT_BUFFER_LEN.copy("nbyte")] , A.LEN.asReturn()],
    [5, "open", 5,  [A.CONST_PATH,A.OFLAGS,A.OMODE] , { t:T.INT32, e:[] }],
    [6, "close", 6,  [A.FD] , { t:T.INT32, e:[] }],
    [7, "wait4", 7,  [A.PID,{ t:T.POINTER64, n:"user_addr_t status" },{ t:T.INT32, n:"options" },A.RUSAGE] , { t:T.INT32, e:[] }],
    [8, "nosys", 8, [] ], // [extra=old creat]
    [9, "link", 9,  [A.CONST_PATH,{ t:T.STRING, n:"link" }] , { t:T.INT32, e:[E.EACCES,E.EDQUOT,E.EEXIST,E.EFAULT,E.EIO,E.ELOOP,E.EMLINK,E.ENOENT,E.ENOSPC,E.ENOTDIR,E.EPERM,E.EROFS,E.EXDEV] }],
    [10, "unlink", 10,  [A.CONST_PATH] , { t:T.INT32, e:[] }],
    [11, "nosys", 11, [] ], // [extra=old execv]
    [12, "chdir", 12,  [A.CONST_PATH] , { t:T.INT32, e:[] }],
    [13, "fchdir", 13,  [A.FD] , { t:T.INT32, e:[] }],
    [14, "mknod", 14,  [A.CONST_PATH,{t:T.INT32, n:"umode", l:L.FLAG, f:X.NODMODE, r:"x3" },{t:T.INT32, n:"dev", l:L.DEV }] , { t:T.INT32, e:[] }],
    [15, "chmod", 15,  [A.CONST_PATH,{t:T.USHORT, n:"mode", l:L.ATTRMODE, f:X.ATTR}] , { t:T.INT32, e:[] }],
    [16, "chown", 16,  [A.CONST_PATH,A.UID,A.GID] , { t:T.INT32, e:[] }],
    [17, "nosys", 17, [] ], // [extra=old break]
    [18, "getfsstat", 18,  [{ t:T.POINTER64, n:"user_addr_t buf" },A.OUTPUT_BUFFER_LEN,{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [19, "nosys", 19, [] ], // [extra=old lseek]
    [20, "getpid", 20,  [] , { t:T.INT32, e:[] }],
    [21, "nosys", 21, [] ], // [extra=old mount]
    [22, "nosys", 22, [] ], // [extra=old umount]
    [23, "setuid", 23,  [A.UID] , { t:T.INT32, e:[] }],
    [24, "getuid", 24,  [] , { t:T.INT32, e:[] }],
    [25, "geteuid", 25,  [] , { t:T.INT32, e:[] }],
    [26, "ptrace", 26,  [{t:T.INT32, n:"request", l:L.FLAG, f:X.PTRACE },A.PID,A.ADDR,{ t:T.INT32, n:"data" }] , { t:T.INT32, e:[] }],
    [27, "recvmsg", 27,  [A.SOCKFD,{ t:"struct msghdr", n:"*msg" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [28, "sendmsg", 28,  [A.SOCKFD,A.ADDR.copy("msg"),{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [29, "recvfrom", 29,  [A.SOCKFD,{ t:T.POINTER64, n:"*buf" },{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"flags" },{ t:"struct sockaddr", n:"*from" },{ t:T.INT32, n:"*fromlenaddr" }] , { t:T.INT32, e:[] }],
    [30, "accept", 30,  [A.SOCKFD,A.ADDR.copy("name"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [31, "getpeername", 31,  [A.SOCKFD,A.SOCKADDR,A.SOCKLEN] , { t:T.INT32, e:[] }],
    [32, "getsockname", 32,  [A.SOCKFD,A.SOCKADDR,A.SOCKLEN] , { t:T.INT32, e:[] }],
    [33, "access", 33,  [A.CONST_PATH,{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [34, "chflags", 34,  [{ T:T.CHAR, n:"*path" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [35, "fchflags", 35,  [A.FD,{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [36, "sync", 36,  [] , { t:T.INT32, e:[] }],
    [37, "kill", 37,  [A.PID,A.SIG,{ t:T.INT32, n:"posix" }] , { t:T.INT32, e:[] }],
    [38, "nosys", 38, [] ], // [extra=old stat ]
    [39, "getppid", 39,  [] , { t:T.INT32, e:[] }],
    [40, "nosys", 40, [] ], // [extra=old lstat]
    [41, "dup", 41,  [{ t:T.UINT32, n:"fd" }] , { t:T.INT32, e:[] }],
    [42, "pipe", 42,  [] , { t:T.INT32, e:[] }],
    [43, "getegid", 43,  [] , { t:T.INT32, e:[] }],
    [44, "profil", 44,  [{ t:"short", n:"*bufbase" },{ t:T.ULONG, n:"bufsize" },{ t:T.ULONG, n:"pcoffset" },{ t:T.UINT32, n:"pcscale" }] , { t:T.INT32, e:[] }],
    [45, "nosys", 45, [] ], // [extra=old ktrace]
    [46, "sigaction", 46,  [A.SIG,A.SIGACTION.copy("*nsa").constant(),A.SIGACTION.copy("*osa")] , { t:T.INT32, e:[] }],
    [47, "getgid", 47,  [] , A.GID.asReturn()],
    [48, "sigprocmask", 48,  [{ t:T.INT32, n:"how" },{ t:"user_addr_t", n:"mask" },{ t:"user_addr_t", n:"omask" }] , { t:T.INT32, e:[] }],
    [49, "getlogin", 49,  [{ T:T.CHAR, n:"*namebuf" },{ t:T.UINT32, n:"namelen" }] , { t:T.INT32, e:[] }],
    [50, "setlogin", 50,  [{ T:T.CHAR, n:"*namebuf" }] , { t:T.INT32, e:[] }],
    [51, "acct", 51,  [{ T:T.CHAR, n:"*path" }] , { t:T.INT32, e:[] }],
    [52, "sigpending", 52,  [{ t:"struct sigvec", n:"*osv" }] , { t:T.INT32, e:[] }],
    [53, "sigaltstack", 53,  [{ t:"struct sigaltstack", n:"*nss" },{ t:"struct sigaltstack", n:"*oss" }] , { t:T.INT32, e:[] }],
    [54, "ioctl", 54,  [A.FD,{ t:T.ULONG, n:"com" },A.ADDR.copy("data")] , { t:T.INT32, e:[] }],
    [55, "reboot", 55,  [{ t:T.INT32, n:"opt" },{ T:T.CHAR, n:"*command" }] , { t:T.INT32, e:[] }],
    [56, "revoke", 56,  [{ T:T.CHAR, n:"*path" }] , { t:T.INT32, e:[] }],
    [57, "symlink", 57,  [{ T:T.CHAR, n:"*path" },{ T:T.CHAR, n:"*link" }] , { t:T.INT32, e:[] }],
    [58, "readlink", 58,  [{ T:T.CHAR, n:"*path" },{ T:T.CHAR, n:"*buf" },{ t:T.INT32, n:"count" }] , { t:T.INT32, e:[] }],
    [59, "execve", 59,  [{ T:T.CHAR, n:"*fname" },{ T:T.CHAR, n:"**argp" },{ T:T.CHAR, n:"**envp" }] , { t:T.INT32, e:[] }],
    [60, "umask", 60,  [{ t:T.INT32, n:"newmask" }] , { t:T.INT32, e:[] }],
    [61, "chroot", 61,  [A.CONST_PATH] , { t:T.INT32, e:[] }],
    [62, "nosys", 62, [] ], // [extra=old fstat]
    [63, "nosys", 63, [] ], // [extra=used internally, reserved]
    [64, "nosys", 64, [] ], // [extra=old getpagesize]
    [65, "msync", 65,  [A.ADDR,{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [66, "vfork", 66,  [] , { t:T.INT32, e:[] }],
    [67, "nosys", 67, [] ], // [extra=old vread]
    [68, "nosys", 68, [] ], // [extra=old vwrite]
    [69, "nosys", 69, [] ], // [extra=old sbrk]
    [70, "nosys", 70, [] ], // [extra=old sstk]
    [71, "nosys", 71, [] ], // [extra=old mmap]
    [72, "nosys", 72, [] ], // [extra=old vadvise]
    [73, "munmap", 73,  [A.ADDR,{ t:T.ULONG, n:"len" }] , { t:T.INT32, e:[] }],
    [74, "mprotect", 74,  [A.ADDR,{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"prot" }] , { t:T.INT32, e:[] }],
    [75, "madvise", 75,  [A.ADDR,{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"behav" }] , { t:T.INT32, e:[] }],
    [76, "nosys", 76, [] ], // [extra=old vhangup]
    [77, "nosys", 77, [] ], // [extra=old vlimit]
    [78, "mincore", 78,  [{ t:"user_addr_t", n:"addr" },{ t:"user_size_t", n:"len" },{ t:"user_addr_t", n:"vec" }] , { t:T.INT32, e:[] }],
    [79, "getgroups", 79,  [{ t:T.UINT32, n:"gidsetsize" },{ t:"gid_t", n:"*gidset" }] , { t:T.INT32, e:[] }],
    [80, "setgroups", 80,  [{ t:T.UINT32, n:"gidsetsize" },{ t:"gid_t", n:"*gidset" }] , { t:T.INT32, e:[] }],
    [81, "getpgrp", 81,  [] , { t:T.INT32, e:[] }],
    [82, "setpgid", 82,  [A.PID,{ t:T.INT32, n:"pgid" }] , { t:T.INT32, e:[] }],
    [83, "setitimer", 83,  [{ t:T.UINT32, n:"which" },{ t:"struct itimerval", n:"*itv" },{ t:"struct itimerval", n:"*oitv" }] , { t:T.INT32, e:[] }],
    [84, "nosys", 84, [] ], // [extra=old wait]
    [85, "swapon", 85,  [] , { t:T.INT32, e:[] }],
    [86, "getitimer", 86,  [{ t:T.UINT32, n:"which" },{ t:"struct itimerval", n:"*itv" }] , { t:T.INT32, e:[] }],
    [87, "nosys", 87, [] ], // [extra=old gethostname]
    [88, "nosys", 88, [] ], // [extra=old sethostname]
    [89, "getdtablesize", 89,  [] , { t:T.INT32, e:[] }],
    [90, "dup2", 90,  [{ t:T.UINT32, n:"from" },{ t:T.UINT32, n:"to" }] , { t:T.INT32, e:[] }],
    [91, "nosys", 91, [] ], // [extra=old getdopt]
    [92, "fcntl", 92,  [A.FD,{ t:T.INT32, n:"cmd" },{ T:T.LONG, n:"arg" }] , { t:T.INT32, e:[] }],
    [93, "select", 93,  [{ t:T.INT32, n:"nd" },{ T:T.UINT32, n:"*in" },{ T:T.UINT32, n:"*ou" },{ T:T.UINT32, n:"*ex" },{ t:"struct timeval", n:"*tv" }] , { t:T.INT32, e:[] }],
    [94, "nosys", 94, [] ], // [extra=old setdopt]
    [95, "fsync", 95,  [A.FD] , { t:T.INT32, e:[] }],
    [96, "setpriority", 96,  [{ t:T.INT32, n:"which" },{ t:"id_t", n:"who" },{ t:T.INT32, n:"prio" }] , { t:T.INT32, e:[] }],
    [97, "socket", 97,  [{ t:T.INT32, n:"domain" },{ t:T.INT32, n:"type" },{ t:T.INT32, n:"protocol" }] , { t:T.INT32, e:[] }],
    [98, "connect", 98,  [A.SOCKFD,A.ADDR.copy("name"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [99, "nosys", 99, [] ], // [extra=old accept]
    [100, "getpriority", 100,  [{ t:T.INT32, n:"which" },{ t:"id_t", n:"who" }] , { t:T.INT32, e:[] }],
    [101, "nosys", 101, [] ], // [extra=old send]
    [102, "nosys", 102, [] ], // [extra=old recv]
    [103, "nosys", 103, [] ], // [extra=old sigreturn]
    [104, "bind", 104,  [A.SOCKFD,A.ADDR.copy("name"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [105, "setsockopt", 105,  [A.SOCKFD,{ t:T.INT32, n:"level" },{ t:T.INT32, n:"name" },A.ADDR.copy("val"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [106, "listen", 106,  [A.SOCKFD,{ t:T.INT32, n:"backlog" }] , { t:T.INT32, e:[] }],
    [107, "nosys", 107, [] ], // [extra=old vtimes]
    [108, "nosys", 108, [] ], // [extra=old sigvec]
    [109, "nosys", 109, [] ], // [extra=old sigblock]
    [110, "nosys", 110, [] ], // [extra=old sigsetmask]
    [111, "sigsuspend", 111,  [{ t:"sigset_t", n:"mask" }] , { t:T.INT32, e:[] }],
    [112, "nosys", 112, [] ], // [extra=old sigstack]
    [113, "nosys", 113, [] ], // [extra=old recvmsg]
    [114, "nosys", 114, [] ], // [extra=old sendmsg]
    [115, "nosys", 115, [] ], // [extra=old vtrace]
    [116, "gettimeofday", 116,  [{ t:"struct timeval", n:"*tp" },{ t:"struct timezone", n:"*tzp" }] , { t:T.INT32, e:[] }],
    [117, "getrusage", 117,  [{ t:T.INT32, n:"who" },{ t:"struct rusage", n:"*rusage" }] , { t:T.INT32, e:[] }],
    [118, "getsockopt", 118,  [A.SOCKFD,{ t:T.INT32, n:"level" },{ t:T.INT32, n:"name" },A.ADDR.copy("val"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [119, "nosys", 119, [] ], // [extra=old resuba]
    [120, "readv", 120,  [A.FD,{ t:"struct iovec", n:"*iovp" },{ t:T.UINT32, n:"iovcnt" }] , A.LEN.asReturn()],
    [121, "writev", 121,  [A.FD,{ t:"struct iovec", n:"*iovp" },{ t:T.UINT32, n:"iovcnt" }] , A.LEN.asReturn()],
    [122, "settimeofday", 122,  [{ t:"struct timeval", n:"*tv" },{ t:"struct timezone", n:"*tzp" }] , { t:T.INT32, e:[] }],
    [123, "fchown", 123,  [A.FD,{ t:T.INT32, n:"uid" },A.GID] , { t:T.INT32, e:[] }],
    [124, "fchmod", 124,  [A.FD,{ t:T.INT32, n:"mode" }] , { t:T.INT32, e:[] }],
    [125, "nosys", 125, [] ], // [extra=old recvfrom]
    [126, "setreuid", 126,  [{ t:"uid_t", n:"ruid" },A.UID.copy("euid")] , { t:T.INT32, e:[] }],
    [127, "setregid", 127,  [{ t:"gid_t", n:"rgid" },A.GID.copy("egid")] , { t:T.INT32, e:[] }],
    [128, "rename", 128,  [A.STR.copy("*from"),A.STR.copy("*to")] , { t:T.INT32, e:[] }],
    [129, "nosys", 129, [] ], // [extra=old truncate]
    [130, "nosys", 130, [] ], // [extra=old ftruncate]
    [131, "flock", 131,  [A.FD,{ t:T.INT32, n:"how" }] , { t:T.INT32, e:[] }],
    [132, "mkfifo", 132,  [A.CONST_PATH,{ t:T.INT32, n:"mode" }] , { t:T.INT32, e:[] }],
    [133, "sendto", 133,  [A.SOCKFD,A.ADDR.copy("buf"),{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"flags" },A.ADDR.copy("to"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [134, "shutdown", 134,  [A.SOCKFD,{ t:T.INT32, n:"how" }] , { t:T.INT32, e:[] }],
    [135, "socketpair", 135,  [{ t:T.INT32, n:"domain" },{ t:T.INT32, n:"type" },{ t:T.INT32, n:"protocol" },{ t:T.INT32, n:"*rsv" }] , { t:T.INT32, e:[] }],
    [136, "mkdir", 136,  [A.CONST_PATH,{ t:T.INT32, n:"mode" }] , { t:T.INT32, e:[] }],
    [137, "rmdir", 137,  [{ T:T.CHAR, n:"*path" }] , { t:T.INT32, e:[] }],
    [138, "utimes", 138,  [{ T:T.CHAR, n:"*path" },{ t:"struct timeval", n:"*tptr" }] , { t:T.INT32, e:[] }],
    [139, "futimes", 139,  [A.FD,{ t:"struct timeval", n:"*tptr" }] , { t:T.INT32, e:[] }],
    [140, "adjtime", 140,  [{ t:"struct timeval", n:"*delta" },{ t:"struct timeval", n:"*olddelta" }] , { t:T.INT32, e:[] }],
    [141, "nosys", 141, [] ], // [extra=old getpeername]
    [142, "gethostuuid", 142,  [{ t:"unsigned char", n:"*uuid_buf" },{ t:"const struct timespec", n:"*timeoutp" }] , { t:T.INT32, e:[] }],
    [143, "nosys", 143, [] ], // [extra=old sethostid ]
    [144, "nosys", 144, [] ], // [extra=old getrlimit]
    [145, "nosys", 145, [] ], // [extra=old setrlimit]
    [146, "nosys", 146, [] ], // [extra=old killpg]
    [147, "setsid", 147,  [] , { t:T.INT32, e:[] }],
    [148, "nosys", 148, [] ], // [extra=old setquota]
    [149, "nosys", 149, [] ], // [extra=old qquota]
    [150, "nosys", 150, [] ], // [extra=old getsockname]
    [151, "getpgid", 151,  [A.PID] , { t:T.INT32, e:[] }],
    [152, "setprivexec", 152,  [{ t:T.INT32, n:"flag" }] , { t:T.INT32, e:[] }],
    [153, "pread", 153,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.LEN.copy("nbyte"),{ t:"off_t", n:"offset" }] , A.LEN.asReturn()],
    [154, "pwrite", 154,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.LEN.copy("nbyte"),{ t:"off_t", n:"offset" }] , A.LEN.asReturn()],
    [155, "nfssvc", 155,  [{ t:T.INT32, n:"flag" },A.ADDR.copy("argp")] , { t:T.INT32, e:[] }],
    [156, "nosys", 156, [] ], // [extra=old getdirentries]
    [157, "statfs", 157,  [{ T:T.CHAR, n:"*path" },{ t:"struct statfs", n:"*buf" }] , { t:T.INT32, e:[] }],
    [158, "fstatfs", 158,  [A.FD,{ t:"struct statfs", n:"*buf" }] , { t:T.INT32, e:[] }],
    [159, "unmount", 159,  [A.CONST_PATH,{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [160, "nosys", 160, [] ], // [extra=old async_daemon]
    [161, "getfh", 161,  [{ T:T.CHAR, n:"*fname" },{ t:"fhandle_t", n:"*fhp" }] , { t:T.INT32, e:[] }],
    [162, "nosys", 162, [] ], // [extra=old getdomainname]
    [163, "nosys", 163, [] ], // [extra=old setdomainname]
    [164, "nosys", 164, [] ],
    [165, "quotactl", 165,  [A.CONST_NAME.copy("*path"),{ t:T.INT32, n:"cmd" },{ t:T.INT32, n:"uid" },A.ADDR.copy("arg")] , { t:T.INT32, e:[] }],
    [166, "nosys", 166, [] ], // [extra=old exportfs]
    [167, "mount", 167,  [{ T:T.CHAR, n:"*type" },{ T:T.CHAR, n:"*path" },{ t:T.INT32, n:"flags" },A.ADDR.copy("data")] , { t:T.INT32, e:[] }],
    [168, "nosys", 168, [] ], // [extra=old ustat]
    [169, "csops", 169,  [A.PID,{ t:T.UINT32, n:"ops" },{ t:"user_addr_t", n:"useraddr" },{ t:"user_size_t", n:"usersize" }] , { t:T.INT32, e:[] }],
    [170, "nosys", 170, [] ], // [extra=old table]
    [171, "nosys", 171, [] ], // [extra=old wait3]
    [172, "nosys", 172, [] ], // [extra=old rpause]
    [173, "waitid", 173,  [{ t:"idtype_t", n:"idtype" },{ t:"id_t", n:"id" },{ t:"siginfo_t", n:"*infop" },{ t:T.INT32, n:"options" }] , { t:T.INT32, e:[] }],
    [174, "nosys", 174, [] ], // [extra=old getdents]
    [175, "nosys", 175, [] ], // [extra=old gc_control]
    [176, "add_profil", 176,  [{ t:"short", n:"*bufbase" },{ t:T.ULONG, n:"bufsize" },{ t:T.ULONG, n:"pcoffset" },{ t:T.UINT32, n:"pcscale" }] , { t:T.INT32, e:[] }],
    [177, "nosys", 177, [] ],
    [178, "nosys", 178, [] ],
    [179, "nosys", 179, [] ],
    [180, "kdebug_trace", 180,  [{ t:T.INT32, n:"code" },{ t:T.INT32, n:"arg1" },{ t:T.INT32, n:"arg2" },{ t:T.INT32, n:"arg3" },{ t:T.INT32, n:"arg4" },{ t:T.INT32, n:"arg5" }] , { t:T.INT32, e:[] }],
    [181, "setgid", 181,  [{ t:"gid_t", n:"gid" }] , { t:T.INT32, e:[] }],
    [182, "setegid", 182,  [A.GID.copy("egid")] , { t:T.INT32, e:[] }],
    [183, "seteuid", 183,  [A.UID.copy("euid")] , { t:T.INT32, e:[] }],
    [184, "sigreturn", 184,  [{ t:"struct ucontext", n:"*uctx" },{ t:T.INT32, n:"infostyle" }] , { t:T.INT32, e:[] }],
    [185, "chud", 185,  [{ t:"uint64_t", n:"code" },{ t:"uint64_t", n:"arg1" },{ t:"uint64_t", n:"arg2" },{ t:"uint64_t", n:"arg3" },{ t:"uint64_t", n:"arg4" },{ t:"uint64_t", n:"arg5" }] , { t:T.INT32, e:[] }],
    [186, "nosys", 186, [] ],
    [187, "fdatasync", 187,  [A.FD] , { t:T.INT32, e:[] }],
    [188, "stat", 188,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" }] , { t:T.INT32, e:[] }],
    [189, "fstat", 189,  [A.FD,{ t:"user_addr_t", n:"ub" }] , { t:T.INT32, e:[] }],
    [190, "lstat", 190,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" }] , { t:T.INT32, e:[] }],
    [191, "pathconf", 191,  [{ T:T.CHAR, n:"*path" },{ t:T.INT32, n:"name" }] , { t:T.INT32, e:[] }],
    [192, "fpathconf", 192,  [A.FD,{ t:T.INT32, n:"name" }] , { t:T.INT32, e:[] }],
    [193, "nosys", 193, [] ],
    [194, "getrlimit", 194,  [{ t:T.UINT32, n:"which" },{ t:"struct rlimit", n:"*rlp" }] , { t:T.INT32, e:[] }],
    [195, "setrlimit", 195,  [{ t:T.UINT32, n:"which" },{ t:"struct rlimit", n:"*rlp" }] , { t:T.INT32, e:[] }],
    [196, "getdirentries", 196,  [A.FD,{ T:T.CHAR, n:"*buf" },{ t:T.UINT32, n:"count" },{ T:T.LONG, n:"*basep" }] , { t:T.INT32, e:[] }],
    [197, "mmap", 197,  [A.ADDR,{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"prot" },{ t:T.INT32, n:"flags" },A.FD,{ t:"off_t", n:"pos" }] , { t:"user_addr_t", e:[] }],
    [198, "nosys", 198, [] ], // [extra=__syscall]
    [199, "lseek", 199,  [A.FD,{ t:"off_t", n:"offset" },{ t:T.INT32, n:"whence" }] , { t:"off_t", e:[] }],
    [200, "truncate", 200,  [{ T:T.CHAR, n:"*path" },{ t:"off_t", n:"length" }] , { t:T.INT32, e:[] }],
    [201, "ftruncate", 201,  [A.FD,{ t:"off_t", n:"length" }] , { t:T.INT32, e:[] }],
    [202, "__sysctl", 202,  [{ t:T.INT32, n:"*name" },{ t:T.UINT32, n:"namelen" },{ t:T.POINTER64, n:"*old" },{ t:T.ULONG, n:"*oldlenp" },{ t:T.POINTER64, n:"*new" },{ t:T.ULONG, n:"newlen" }] , { t:T.INT32, e:[] }],
    [203, "mlock", 203,  [A.ADDR,{ t:T.ULONG, n:"len" }] , { t:T.INT32, e:[] }],
    [204, "munlock", 204,  [A.ADDR,{ t:T.ULONG, n:"len" }] , { t:T.INT32, e:[] }],
    [205, "undelete", 205,  [A.CONST_PATH] , { t:T.INT32, e:[] }],
    [206, "ATsocket", 206,  [{ t:T.INT32, n:"proto" }] , { t:T.INT32, e:[] }],
    [207, "ATgetmsg", 207,  [A.FD,{ t:T.POINTER64, n:"*ctlptr" },{ t:T.POINTER64, n:"*datptr" },{ t:T.INT32, n:"*flags" }] , { t:T.INT32, e:[] }],
    [208, "ATputmsg", 208,  [A.FD,{ t:T.POINTER64, n:"*ctlptr" },{ t:T.POINTER64, n:"*datptr" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [209, "ATPsndreq", 209,  [A.FD,{ t:"unsigned char", n:"*buf" },{ t:T.INT32, n:"len" },{ t:T.INT32, n:"nowait" }] , { t:T.INT32, e:[] }],
    [210, "ATPsndrsp", 210,  [A.FD,{ t:"unsigned char", n:"*respbuff" },{ t:T.INT32, n:"resplen" },{ t:T.INT32, n:"datalen" }] , { t:T.INT32, e:[] }],
    [211, "ATPgetreq", 211,  [A.FD,{ t:"unsigned char", n:"*buf" },{ t:T.INT32, n:"buflen" }] , { t:T.INT32, e:[] }],
    [212, "ATPgetrsp", 212,  [A.FD,{ t:"unsigned char", n:"*bdsp" }] , { t:T.INT32, e:[] }],
    [213, "nosys", 213, [] ], // [extra=Reserved{ t:"for", n:"AppleTalk" }]
    [214, "nosys", 214, [] ],
    [215, "nosys", 215, [] ],
    [216, "mkcomplex", 216,  [A.CONST_NAME.copy("*path"),{ t:"mode_t", n:"mode" },{ t:T.ULONG, n:"type" }] , { t:T.INT32, e:[] }], // [extra=soon{ t:"to be", n:"obsolete" }]
    [217, "statv", 217,  [A.CONST_NAME.copy("*path"),{ t:"struct vstat", n:"*vsb" }] , { t:T.INT32, e:[] }], // [extra=soon{ t:"to be", n:"obsolete" }]
    [218, "lstatv", 218,  [A.CONST_NAME.copy("*path"),{ t:"struct vstat", n:"*vsb" }] , { t:T.INT32, e:[] }], // [extra=soon{ t:"to be", n:"obsolete" }]
    [219, "fstatv", 219,  [A.FD,{ t:"struct vstat", n:"*vsb" }] , { t:T.INT32, e:[] }], // [extra=soon{ t:"to be", n:"obsolete" }]
    [220, "getattrlist", 220,  [A.CONST_NAME.copy("*path"),{ t:"struct attrlist", n:"*alist" },{ t:T.POINTER64, n:"*attributeBuffer" },{ t:T.ULONG, n:"bufferSize" },{ t:T.ULONG, n:"options" }] , { t:T.INT32, e:[] }],
    [221, "setattrlist", 221,  [A.CONST_NAME.copy("*path"),{ t:"struct attrlist", n:"*alist" },{ t:T.POINTER64, n:"*attributeBuffer" },{ t:T.ULONG, n:"bufferSize" },{ t:T.ULONG, n:"options" }] , { t:T.INT32, e:[] }],
    [222, "getdirentriesattr", 222,  [A.FD,{ t:"struct attrlist", n:"*alist" },{ t:T.POINTER64, n:"*buffer" },{ t:T.ULONG, n:"buffersize" },{ t:T.ULONG, n:"*count" },{ t:T.ULONG, n:"*basep" },{ t:T.ULONG, n:"*newstate" },{ t:T.ULONG, n:"options" }] , { t:T.INT32, e:[] }],
    [223, "exchangedata", 223,  [A.CONST_NAME.copy("*path1"),A.CONST_NAME.copy("*path2"),{ t:T.ULONG, n:"options" }] , { t:T.INT32, e:[] }],
    [224, "nosys", 224, [] ], // [extra=old checkuseraccess / fsgetpath (which{ t:"moved to", n:"427" })]
    [225, "searchfs", 225,  [A.CONST_NAME.copy("*path"),{ t:"struct fssearchblock", n:"*searchblock" },{ t:T.UINT32, n:"*nummatches" },{ t:T.UINT32, n:"scriptcode" },{ t:T.UINT32, n:"options" },{ t:"struct searchstate", n:"*state" }] , { t:T.INT32, e:[] }],
    [226, "delete", 226,  [A.CONST_PATH] , { t:T.INT32, e:[] }],  // [extra=private delete (Carbon semantics)]
    [227, "copyfile", 227,  [A.STR.copy("*from"),A.STR.copy("*to"),{ t:T.INT32, n:"mode" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [228, "fgetattrlist", 228,  [A.FD,{ t:"struct attrlist", n:"*alist" },{ t:T.POINTER64, n:"*attributeBuffer" },{ t:T.ULONG, n:"bufferSize" },{ t:T.ULONG, n:"options" }] , { t:T.INT32, e:[] }],
    [229, "fsetattrlist", 229,  [A.FD,{ t:"struct attrlist", n:"*alist" },{ t:T.POINTER64, n:"*attributeBuffer" },{ t:T.ULONG, n:"bufferSize" },{ t:T.ULONG, n:"options" }] , { t:T.INT32, e:[] }],
    [230, "poll", 230,  [{ t:"struct pollfd", n:"*fds" },{ t:T.UINT32, n:"nfds" },{ t:T.INT32, n:"timeout" }] , { t:T.INT32, e:[] }],
    [231, "watchevent", 231,  [{ t:"struct eventreq", n:"*u_req" },{ t:T.INT32, n:"u_eventmask" }] , { t:T.INT32, e:[] }],
    [232, "waitevent", 232,  [{ t:"struct eventreq", n:"*u_req" },{ t:"struct timeval", n:"*tv" }] , { t:T.INT32, e:[] }],
    [233, "modwatch", 233,  [{ t:"struct eventreq", n:"*u_req" },{ t:T.INT32, n:"u_eventmask" }] , { t:T.INT32, e:[] }],
    [234, "getxattr", 234,  [A.CONST_PATH,{ t:"user_addr_t", n:"attrname" },{ t:"user_addr_t", n:"value" },{ t:T.ULONG, n:"size" },{ t:T.UINT32, n:"position" },{ t:T.INT32, n:"options" }] , A.LEN.asReturn()],
    [235, "fgetxattr", 235,  [A.FD,{ t:"user_addr_t", n:"attrname" },{ t:"user_addr_t", n:"value" },{ t:T.ULONG, n:"size" },{ t:T.UINT32, n:"position" },{ t:T.INT32, n:"options" }] , A.LEN.asReturn()],
    [236, "setxattr", 236,  [A.CONST_PATH,{ t:"user_addr_t", n:"attrname" },{ t:"user_addr_t", n:"value" },{ t:T.ULONG, n:"size" },{ t:T.UINT32, n:"position" },{ t:T.INT32, n:"options" }] , { t:T.INT32, e:[] }],
    [237, "fsetxattr", 237,  [A.FD,{ t:"user_addr_t", n:"attrname" },{ t:"user_addr_t", n:"value" },{ t:T.ULONG, n:"size" },{ t:T.UINT32, n:"position" },{ t:T.INT32, n:"options" }] , { t:T.INT32, e:[] }],
    [238, "removexattr", 238,  [A.CONST_PATH,{ t:"user_addr_t", n:"attrname" },{ t:T.INT32, n:"options" }] , { t:T.INT32, e:[] }],
    [239, "fremovexattr", 239,  [A.FD,{ t:"user_addr_t", n:"attrname" },{ t:T.INT32, n:"options" }] , { t:T.INT32, e:[] }],
    [240, "listxattr", 240,  [A.CONST_PATH,{ t:"user_addr_t", n:"namebuf" },{ t:T.ULONG, n:"bufsize" },{ t:T.INT32, n:"options" }] , A.LEN.asReturn()],
    [241, "flistxattr", 241,  [A.FD,{ t:"user_addr_t", n:"namebuf" },{ t:T.ULONG, n:"bufsize" },{ t:T.INT32, n:"options" }] , A.LEN.asReturn()],
    [242, "fsctl", 242,  [A.CONST_NAME.copy("*path"),{ t:T.ULONG, n:"cmd" },A.ADDR.copy("data"),{ t:T.UINT32, n:"options" }] , { t:T.INT32, e:[] }],
    [243, "initgroups", 243,  [{ t:T.UINT32, n:"gidsetsize" },{ t:"gid_t", n:"*gidset" },{ t:T.INT32, n:"gmuid" }] , { t:T.INT32, e:[] }],
    [244, "posix_spawn", 244,  [{ t:"pid_t", n:"*pid" },A.CONST_NAME.copy("*path"),{ t:"const struct _posix_spawn_args_desc", n:"*adesc" },{ T:T.CHAR, n:"**argv" },{ T:T.CHAR, n:"**envp" }] , { t:T.INT32, e:[] }],
    [245, "ffsctl", 245,  [A.FD,{ t:T.ULONG, n:"cmd" },A.ADDR.copy("data"),{ t:T.UINT32, n:"options" }] , { t:T.INT32, e:[] }],
    [246, "nosys", 246, [] ],
    [247, "nfsclnt", 247,  [{ t:T.INT32, n:"flag" },A.ADDR.copy("argp")] , { t:T.INT32, e:[] }],
    [248, "fhopen", 248,  [{ t:"const struct fhandle", n:"*u_fhp" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [249, "nosys", 249, [] ],
    [250, "minherit", 250,  [{ t:T.POINTER64, n:"*addr" },{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"inherit" }] , { t:T.INT32, e:[] }],
    [251, "semsys", 251,  [{ t:T.UINT32, n:"which" },{ t:T.INT32, n:"a2" },{ t:T.INT32, n:"a3" },{ t:T.INT32, n:"a4" },{ t:T.INT32, n:"a5" }] , { t:T.INT32, e:[] }],
    [252, "msgsys", 252,  [{ t:T.UINT32, n:"which" },{ t:T.INT32, n:"a2" },{ t:T.INT32, n:"a3" },{ t:T.INT32, n:"a4" },{ t:T.INT32, n:"a5" }] , { t:T.INT32, e:[] }],
    [253, "shmsys", 253,  [{ t:T.UINT32, n:"which" },{ t:T.INT32, n:"a2" },{ t:T.INT32, n:"a3" },{ t:T.INT32, n:"a4" }] , { t:T.INT32, e:[] }],
    [254, "semctl", 254,  [{ t:T.INT32, n:"semid" },{ t:T.INT32, n:"semnum" },{ t:T.INT32, n:"cmd" },{ t:"semun_t", n:"arg" }] , { t:T.INT32, e:[] }],
    [255, "semget", 255,  [{ t:"key_t", n:"key" },{ t:T.INT32, n:"nsems" },{ t:T.INT32, n:"semflg" }] , { t:T.INT32, e:[] }],
    [256, "semop", 256,  [{ t:T.INT32, n:"semid" },{ t:"struct sembuf", n:"*sops" },{ t:T.INT32, n:"nsops" }] , { t:T.INT32, e:[] }],
    [257, "nosys", 257, [] ],
    [258, "msgctl", 258,  [{ t:T.INT32, n:"msqid" },{ t:T.INT32, n:"cmd" },{ t:"struct	msqid_ds", n:"*buf" }] , { t:T.INT32, e:[] }],
    [259, "msgget", 259,  [{ t:"key_t", n:"key" },{ t:T.INT32, n:"msgflg" }] , { t:T.INT32, e:[] }],
    [260, "msgsnd", 260,  [{ t:T.INT32, n:"msqid" },{ t:T.POINTER64, n:"*msgp" },{ t:T.ULONG, n:"msgsz" },{ t:T.INT32, n:"msgflg" }] , { t:T.INT32, e:[] }],
    [261, "msgrcv", 261,  [{ t:T.INT32, n:"msqid" },{ t:T.POINTER64, n:"*msgp" },{ t:T.ULONG, n:"msgsz" },{ T:T.LONG, n:"msgtyp" },{ t:T.INT32, n:"msgflg" }] , A.LEN.asReturn()],
    [262, "shmat", 262,  [{ t:T.INT32, n:"shmid" },{ t:T.POINTER64, n:"*shmaddr" },{ t:T.INT32, n:"shmflg" }] , { t:"user_addr_t", e:[] }],
    [263, "shmctl", 263,  [{ t:T.INT32, n:"shmid" },{ t:T.INT32, n:"cmd" },{ t:"struct shmid_ds", n:"*buf" }] , { t:T.INT32, e:[] }],
    [264, "shmdt", 264,  [{ t:T.POINTER64, n:"*shmaddr" }] , { t:T.INT32, e:[] }],
    [265, "shmget", 265,  [{ t:"key_t", n:"key" },{ t:T.ULONG, n:"size" },{ t:T.INT32, n:"shmflg" }] , { t:T.INT32, e:[] }],
    [266, "shm_open", 266,  [A.CONST_NAME.copy("*name"),{ t:T.INT32, n:"oflag" },{ t:T.INT32, n:"mode" }] , { t:T.INT32, e:[] }],
    [267, "shm_unlink", 267,  [A.CONST_NAME.copy("*name")] , { t:T.INT32, e:[] }],
    [268, "sem_open", 268,  [A.CONST_NAME.copy("*name"),{ t:T.INT32, n:"oflag" },{ t:T.INT32, n:"mode" },{ t:T.INT32, n:"value" }] , { t:"user_addr_t", e:[] }],
    [269, "sem_close", 269,  [{ t:"sem_t", n:"*sem" }] , { t:T.INT32, e:[] }],
    [270, "sem_unlink", 270,  [A.CONST_NAME.copy("*name")] , { t:T.INT32, e:[] }],
    [271, "sem_wait", 271,  [{ t:"sem_t", n:"*sem" }] , { t:T.INT32, e:[] }],
    [272, "sem_trywait", 272,  [{ t:"sem_t", n:"*sem" }] , { t:T.INT32, e:[] }],
    [273, "sem_post", 273,  [{ t:"sem_t", n:"*sem" }] , { t:T.INT32, e:[] }],
    [274, "sem_getvalue", 274,  [{ t:"sem_t", n:"*sem" },{ t:T.INT32, n:"*sval" }] , { t:T.INT32, e:[] }],
    [275, "sem_init", 275,  [{ t:"sem_t", n:"*sem" },{ t:T.INT32, n:"phsared" },{ t:T.UINT32, n:"value" }] , { t:T.INT32, e:[] }],
    [276, "sem_destroy", 276,  [{ t:"sem_t", n:"*sem" }] , { t:T.INT32, e:[] }],
    [277, "open_extended", 277,  [A.CONST_PATH,{ t:T.INT32, n:"flags" },A.UID,{ t:"gid_t", n:"gid" },{ t:T.INT32, n:"mode" },{ t:"user_addr_t", n:"xsecurity" }] , { t:T.INT32, e:[] }],
    [278, "umask_extended", 278,  [{ t:T.INT32, n:"newmask" },{ t:"user_addr_t", n:"xsecurity" }] , { t:T.INT32, e:[] }],
    [279, "stat_extended", 279,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" },{ t:"user_addr_t", n:"xsecurity" },{ t:"user_addr_t", n:"xsecurity_size" }] , { t:T.INT32, e:[] }],
    [280, "lstat_extended", 280,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" },{ t:"user_addr_t", n:"xsecurity" },{ t:"user_addr_t", n:"xsecurity_size" }] , { t:T.INT32, e:[] }],
    [281, "fstat_extended", 281,  [A.FD,{ t:"user_addr_t", n:"ub" },{ t:"user_addr_t", n:"xsecurity" },{ t:"user_addr_t", n:"xsecurity_size" }] , { t:T.INT32, e:[] }],
    [282, "chmod_extended", 282,  [A.CONST_PATH,A.UID,{ t:"gid_t", n:"gid" },{ t:T.INT32, n:"mode" },{ t:"user_addr_t", n:"xsecurity" }] , { t:T.INT32, e:[] }],
    [283, "fchmod_extended", 283,  [A.FD,A.UID,{ t:"gid_t", n:"gid" },{ t:T.INT32, n:"mode" },{ t:"user_addr_t", n:"xsecurity" }] , { t:T.INT32, e:[] }],
    [284, "access_extended", 284,  [{ t:"user_addr_t", n:"entries" },{ t:T.ULONG, n:"size" },{ t:"user_addr_t", n:"results" },A.UID] , { t:T.INT32, e:[] }],
    [285, "settid", 285,  [A.UID,{ t:"gid_t", n:"gid" }] , { t:T.INT32, e:[] }],
    [286, "gettid", 286,  [{ t:"uid_t", n:"*uidp" },{ t:"gid_t", n:"*gidp" }] , { t:T.INT32, e:[] }],
    [287, "setsgroups", 287,  [{ t:T.INT32, n:"setlen" },{ t:"user_addr_t", n:"guidset" }] , { t:T.INT32, e:[] }],
    [288, "getsgroups", 288,  [{ t:"user_addr_t", n:"setlen" },{ t:"user_addr_t", n:"guidset" }] , { t:T.INT32, e:[] }],
    [289, "setwgroups", 289,  [{ t:T.INT32, n:"setlen" },{ t:"user_addr_t", n:"guidset" }] , { t:T.INT32, e:[] }],
    [290, "getwgroups", 290,  [{ t:"user_addr_t", n:"setlen" },{ t:"user_addr_t", n:"guidset" }] , { t:T.INT32, e:[] }],
    [291, "mkfifo_extended", 291,  [A.CONST_PATH,A.UID,{ t:"gid_t", n:"gid" },{ t:T.INT32, n:"mode" },{ t:"user_addr_t", n:"xsecurity" }] , { t:T.INT32, e:[] }],
    [292, "mkdir_extended", 292,  [A.CONST_PATH,A.UID,{ t:"gid_t", n:"gid" },{ t:T.INT32, n:"mode" },{ t:"user_addr_t", n:"xsecurity" }] , { t:T.INT32, e:[] }],
    [293, "identitysvc", 293,  [{ t:T.INT32, n:"opcode" },{ t:"user_addr_t", n:"message" }] , { t:T.INT32, e:[] }],
    [294, "shared_region_check_np", 294,  [{ t:"uint64_t", n:"*start_address" }] , { t:T.INT32, e:[] }],
    [295, "shared_region_map_np", 295,  [A.FD,{ t:T.UINT32, n:"count" },{ t:"const struct shared_file_mapping_np", n:"*mappings" }] , { t:T.INT32, e:[] }],
    [296, "vm_pressure_monitor", 296,  [{ t:T.INT32, n:"wait_for_pressure" },{ t:T.INT32, n:"nsecs_monitored" },{ t:T.UINT32, n:"*pages_reclaimed" }] , { t:T.INT32, e:[] }],
    [297, "psynch_rw_longrdlock", 297,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [298, "psynch_rw_yieldwrlock", 298,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [299, "psynch_rw_downgrade", 299,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [300, "psynch_rw_upgrade", 300,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [301, "psynch_mutexwait", 301,  [{ t:"user_addr_t", n:"mutex" },{ t:" uint32_t", n:"mgen" },{ t:"uint32_t ", n:"ugen" },{ t:"uint64_t", n:"tid" },{ t:T.UINT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [302, "psynch_mutexdrop", 302,  [{ t:"user_addr_t", n:"mutex" },{ t:" uint32_t", n:"mgen" },{ t:"uint32_t ", n:"ugen" },{ t:"uint64_t", n:"tid" },{ t:T.UINT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [303, "psynch_cvbroad", 303,  [{ t:"user_addr_t", n:"cv" },{ t:T.UINT32, n:"cvgen" },{ t:T.UINT32, n:"diffgen" },{ t:"user_addr_t", n:"mutex" },{ t:" uint32_t", n:"mgen" },{ t:T.UINT32, n:"ugen" },{ t:"uint64_t", n:"tid" },{ t:T.UINT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [304, "psynch_cvsignal", 304,  [{ t:"user_addr_t", n:"cv" },{ t:T.UINT32, n:"cvgen" },{ t:T.UINT32, n:"cvugen" },{ t:"user_addr_t", n:"mutex" },{ t:" uint32_t", n:"mgen" },{ t:T.UINT32, n:"ugen" },{ t:T.INT32, n:"thread_port" },{ t:T.UINT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [305, "psynch_cvwait", 305,  [{ t:"user_addr_t", n:"cv" },{ t:T.UINT32, n:"cvgen" },{ t:T.UINT32, n:"cvugen" },{ t:"user_addr_t", n:"mutex" },{ t:" uint32_t", n:"mgen" },{ t:T.UINT32, n:"ugen" },{ t:"uint64_t", n:"sec" },{ t:"uint64_t", n:"usec" }] , { t:T.UINT32, e:[] }],
    [306, "psynch_rw_rdlock", 306,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [307, "psynch_rw_wrlock", 307,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [308, "psynch_rw_unlock", 308,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [309, "psynch_rw_unlock2", 309,  [{ t:"user_addr_t", n:"rwlock" },{ t:T.UINT32, n:"lgenval" },{ t:T.UINT32, n:"ugenval" },{ t:T.UINT32, n:"rw_wc" },{ t:T.INT32, n:"flags" }] , { t:T.UINT32, e:[] }],
    [310, "getsid", 310,  [A.PID] , { t:T.INT32, e:[] }],
    [311, "settid_with_pid", 311,  [A.PID,{ t:T.INT32, n:"assume" }] , { t:T.INT32, e:[] }],
    [312, "nosys", 312, [] ], // [extra=old __pthread_cond_timedwait]
    [313, "aio_fsync", 313,  [{ t:T.INT32, n:"op" },A.AIOCBP] , { t:T.INT32, e:[] }],
    [314, "aio_return", 314,  [A.AIOCBP] , A.LEN.asReturn()],
    [315, "aio_suspend", 315,  [{ t:"user_addr_t", n:"aiocblist" },{ t:T.INT32, n:"nent" },{ t:"user_addr_t", n:"timeoutp" }] , { t:T.INT32, e:[] }],
    [316, "aio_cancel", 316,  [A.FD,A.AIOCBP] , { t:T.INT32, e:[] }],
    [317, "aio_error", 317,  [A.AIOCBP] , { t:T.INT32, e:[] }],
    [318, "aio_read", 318,  [A.AIOCBP] , { t:T.INT32, e:[] }],
    [319, "aio_write", 319,  [A.AIOCBP] , { t:T.INT32, e:[] }],
    [320, "lio_listio", 320,  [{ t:T.INT32, n:"mode" },{ t:"user_addr_t", n:"aiocblist" },{ t:T.INT32, n:"nent" },{ t:"user_addr_t", n:"sigp" }] , { t:T.INT32, e:[] }],
    [321, "nosys", 321, [] ], // [extra=old __pthread_cond_wait]
    [322, "iopolicysys", 322,  [{ t:T.INT32, n:"cmd" },{ t:T.POINTER64, n:"*arg" }] , { t:T.INT32, e:[] }],
    [323, "nosys", 323, [] ],
    [324, "mlockall", 324,  [{ t:T.INT32, n:"how" }] , { t:T.INT32, e:[] }],
    [325, "munlockall", 325,  [{ t:T.INT32, n:"how" }] , { t:T.INT32, e:[] }],
    [326, "nosys", 326, [] ],
    [327, "issetugid", 327,  [] , { t:T.INT32, e:[] }],
    [328, "__pthread_kill", 328,  [{ t:T.INT32, n:"thread_port" },{ t:T.INT32, n:"sig" }] , { t:T.INT32, e:[] }],
    [329, "__pthread_sigmask", 329,  [{ t:T.INT32, n:"how" },{ t:"user_addr_t", n:"set" },{ t:"user_addr_t", n:"oset" }] , { t:T.INT32, e:[] }],
    [330, "__sigwait", 330,  [{ t:"user_addr_t", n:"set" },{ t:"user_addr_t", n:"sig" }] , { t:T.INT32, e:[] }],
    [331, "__disable_threadsignal", 331,  [{ t:T.INT32, n:"value" }] , { t:T.INT32, e:[] }],
    [332, "__pthread_markcancel", 332,  [{ t:T.INT32, n:"thread_port" }] , { t:T.INT32, e:[] }],
    [333, "__pthread_canceled", 333,  [{ t:T.INT32, n:"action" }] , { t:T.INT32, e:[] }],
    [334, "__semwait_signal", 334,  [{ t:T.INT32, n:"cond_sem" },{ t:T.INT32, n:"mutex_sem" },{ t:T.INT32, n:"timeout" },{ t:T.INT32, n:"relative" },{ t:"int64_t", n:"tv_sec" },{ t:"int32_t", n:"tv_nsec" }] , { t:T.INT32, e:[] }],
    [335, "nosys", 335, [] ], // [extra=old utrace]
    [336, "proc_info", 336,  [{ t:"int32_t", n:"callnum" },A.PID,{ t:T.UINT32, n:"flavor", l:L.FLAG, f:X.PROC_INFO },{ t:"uint64_t", n:"arg" },{ t:T.POINTER64, n:"buff", l:L.BUFFER },A.SIZE ] , { t:T.INT32, e:[] }],
    [337, "sendfile", 337,  [A.FD,A.SOCKFD,{ t:"off_t", n:"offset" },{ t:"off_t", n:"*nbytes" },{ t:"struct sf_hdtr", n:"*hdtr" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [338, "stat64", 338,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" }] , { t:T.INT32, e:[] }],
    [339, "fstat64", 339,  [A.FD,{ t:"user_addr_t", n:"ub" }] , { t:T.INT32, e:[] }],
    [340, "lstat64", 340,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" }] , { t:T.INT32, e:[] }],
    [341, "stat64_extended", 341,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" },{ t:"user_addr_t", n:"xsecurity" },{ t:"user_addr_t", n:"xsecurity_size" }] , { t:T.INT32, e:[] }],
    [342, "lstat64_extended", 342,  [A.CONST_PATH,{ t:"user_addr_t", n:"ub" },{ t:"user_addr_t", n:"xsecurity" },{ t:"user_addr_t", n:"xsecurity_size" }] , { t:T.INT32, e:[] }],
    [343, "fstat64_extended", 343,  [A.FD,{ t:"user_addr_t", n:"ub" },{ t:"user_addr_t", n:"xsecurity" },{ t:"user_addr_t", n:"xsecurity_size" }] , { t:T.INT32, e:[] }],
    [344, "getdirentries64", 344,  [A.FD,{ t:T.POINTER64, n:"*buf" },{ t:"user_size_t", n:"bufsize" },{ t:"off_t", n:"*position" }] , A.LEN.asReturn()],
    [345, "statfs64", 345,  [{ T:T.CHAR, n:"*path" },{ t:"struct statfs64", n:"*buf" }] , { t:T.INT32, e:[] }],
    [346, "fstatfs64", 346,  [A.FD,{ t:"struct statfs64", n:"*buf" }] , { t:T.INT32, e:[] }],
    [347, "getfsstat64", 347,  [A.OUTPUT_CHAR_BUFFER,{ t:T.INT32, n:"bufsize" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [348, "__pthread_chdir", 348,  [A.CONST_PATH] , { t:T.INT32, e:[] }],
    [349, "__pthread_fchdir", 349,  [A.FD] , { t:T.INT32, e:[] }],
    [350, "audit", 350,  [{ t:T.POINTER64, n:"*record" },{ t:T.INT32, n:"length" }] , { t:T.INT32, e:[] }],
    [351, "auditon", 351,  [{ t:T.INT32, n:"cmd" },{ t:T.POINTER64, n:"*data" },{ t:T.INT32, n:"length" }] , { t:T.INT32, e:[] }],
    [352, "nosys", 352, [] ],
    [353, "getauid", 353,  [{ t:"au_id_t", n:"*auid" }] , { t:T.INT32, e:[] }],
    [354, "setauid", 354,  [{ t:"au_id_t", n:"*auid" }] , { t:T.INT32, e:[] }],
    [355, "getaudit", 355,  [{ t:"struct auditinfo", n:"*auditinfo" }] , { t:T.INT32, e:[] }],
    [356, "setaudit", 356,  [{ t:"struct auditinfo", n:"*auditinfo" }] , { t:T.INT32, e:[] }],
    [357, "getaudit_addr", 357,  [{ t:"struct auditinfo_addr", n:"*auditinfo_addr" },{ t:T.INT32, n:"length" }] , { t:T.INT32, e:[] }],
    [358, "setaudit_addr", 358,  [{ t:"struct auditinfo_addr", n:"*auditinfo_addr" },{ t:T.INT32, n:"length" }] , { t:T.INT32, e:[] }],
    [359, "auditctl", 359,  [{ T:T.CHAR, n:"*path" }] , { t:T.INT32, e:[] }],
    [360, "bsdthread_create", 360,  [{ t:"user_addr_t", n:"func" },{ t:"user_addr_t", n:"func_arg" },{ t:"user_addr_t", n:"stack" },{ t:"user_addr_t", n:"pthread" },{ t:T.UINT32, n:"flags" }] , { t:"user_addr_t", e:[] }],
    [361, "bsdthread_terminate", 361,  [{ t:"user_addr_t", n:"stackaddr" },{ t:T.ULONG, n:"freesize" },{ t:T.UINT32, n:"port" },{ t:T.UINT32, n:"sem" }] , { t:T.INT32, e:[] }],
    [362, "kqueue", 362,  [] , { t:T.INT32, e:[] }],
    [363, "kevent", 363,  [A.FD,{ t:"const struct kevent", n:"*changelist" },{ t:T.INT32, n:"nchanges" },{ t:"struct kevent", n:"*eventlist" },{ t:T.INT32, n:"nevents" },{ t:"const struct timespec", n:"*timeout" }] , { t:T.INT32, e:[] }],
    [364, "lchown", 364,  [A.CONST_PATH,{ t:"uid_t", n:"owner" },{ t:"gid_t", n:"group" }] , { t:T.INT32, e:[] }],
    [365, "stack_snapshot", 365,  [A.PID,{ t:"user_addr_t", n:"tracebuf" },{ t:T.UINT32, n:"tracebuf_size" },{ t:T.UINT32, n:"flags" },{ t:T.UINT32, n:"dispatch_offset" }] , { t:T.INT32, e:[] }],
    [366, "bsdthread_register", 366,  [{ t:"user_addr_t", n:"threadstart" },{ t:"user_addr_t", n:"wqthread" },{ t:T.INT32, n:"pthsize" },{t:"user_addr_t", n:"dummy_value"},{ t:"user_addr_t", n:"targetconc_ptr" },{ t:"uint64_t", n:"dispatchqueue_offset" }] , { t:T.INT32, e:[] }],
    [367, "workq_open", 367,  [] , { t:T.INT32, e:[] }],
    [368, "workq_kernreturn", 368,  [{ t:T.INT32, n:"options" },{ t:"user_addr_t", n:"item" },{ t:T.INT32, n:"affinity" },{ t:T.INT32, n:"prio" }] , { t:T.INT32, e:[] }],
    [369, "kevent64", 369,  [A.FD,{ t:"const struct kevent64_s", n:"*changelist" },{ t:T.INT32, n:"nchanges" },{ t:"struct kevent64_s", n:"*eventlist" },{ t:T.INT32, n:"nevents" },{ t:"unsigned int", n:"flags" },{ t:"const struct timespec", n:"*timeout" }] , { t:T.INT32, e:[] }],
    [370, "__old_semwait_signal", 370,  [{ t:T.INT32, n:"cond_sem" },{ t:T.INT32, n:"mutex_sem" },{ t:T.INT32, n:"timeout" },{ t:T.INT32, n:"relative" },{ t:"const struct timespec", n:"*ts" }] , { t:T.INT32, e:[] }],
    [371, "__old_semwait_signal_nocancel", 371,  [{ t:T.INT32, n:"cond_sem" },{ t:T.INT32, n:"mutex_sem" },{ t:T.INT32, n:"timeout" },{ t:T.INT32, n:"relative" },{ t:"const struct timespec", n:"*ts" }] , { t:T.INT32, e:[] }],
    [372, "thread_selfid", 372,  [] , { t:"user_addr_t", e:[] }],
    [380, "__mac_execve", 380,  [{ T:T.CHAR, n:"*fname" },{ T:T.CHAR, n:"**argp" },{ T:T.CHAR, n:"**envp" },{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [381, "__mac_syscall", 381,  [{ T:T.CHAR, n:"*policy" },{ t:T.INT32, n:"call" },{ t:"user_addr_t", n:"arg" }] , { t:T.INT32, e:[] }],
    [382, "__mac_get_file", 382,  [{ T:T.CHAR, n:"*path_p" },{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [383, "__mac_set_file", 383,  [{ T:T.CHAR, n:"*path_p" },{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [384, "__mac_get_link", 384,  [{ T:T.CHAR, n:"*path_p" },{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [385, "__mac_set_link", 385,  [{ T:T.CHAR, n:"*path_p" },{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [386, "__mac_get_proc", 386,  [{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [387, "__mac_set_proc", 387,  [{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [388, "__mac_get_fd", 388,  [A.FD,{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [389, "__mac_set_fd", 389,  [A.FD,{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [390, "__mac_get_pid", 390,  [A.PID,{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [391, "__mac_get_lcid", 391,  [{ t:"pid_t", n:"lcid" },{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [392, "__mac_get_lctx", 392,  [{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [393, "__mac_set_lctx", 393,  [{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [394, "setlcid", 394,  [A.PID,{ t:"pid_t", n:"lcid" }] , { t:T.INT32, e:[] }],
    [395, "getlcid", 395,  [A.PID] , { t:T.INT32, e:[] }],
    [396, "read_nocancel", 396,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.LEN.copy("nbyte")] , A.LEN.asReturn()],
    [397, "write_nocancel", 397,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.LEN.copy("nbyte")] , A.LEN.asReturn()],
    [398, "open_nocancel", 398,  [A.CONST_PATH,{ t:T.INT32, n:"flags" },{ t:T.INT32, n:"mode" }] , { t:T.INT32, e:[] }],
    [399, "close_nocancel", 399,  [A.FD] , { t:T.INT32, e:[] }],
    [400, "wait4_nocancel", 400,  [A.PID,{ t:"user_addr_t", n:"status" },{ t:T.INT32, n:"options" },A.RUSAGE] , { t:T.INT32, e:[] }],
    [401, "recvmsg_nocancel", 401,  [A.SOCKFD,{ t:"struct msghdr", n:"*msg" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [402, "sendmsg_nocancel", 402,  [A.SOCKFD,A.ADDR.copy("msg"),{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [403, "recvfrom_nocancel", 403,  [A.SOCKFD,{ t:T.POINTER64, n:"*buf" },{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"flags" },{ t:"struct sockaddr", n:"*from" },{ t:T.INT32, n:"*fromlenaddr" }] , { t:T.INT32, e:[] }],
    [404, "accept_nocancel", 404,  [A.SOCKFD,A.ADDR.copy("name"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [405, "msync_nocancel", 405,  [A.ADDR,{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [406, "fcntl_nocancel", 406,  [A.FD,{ t:T.INT32, n:"cmd" },{ T:T.LONG, n:"arg" }] , { t:T.INT32, e:[] }],
    [407, "select_nocancel", 407,  [{ t:T.INT32, n:"nd" },{ T:T.UINT32, n:"*in" },{ T:T.UINT32, n:"*ou" },{ T:T.UINT32, n:"*ex" },{ t:"struct timeval", n:"*tv" }] , { t:T.INT32, e:[] }],
    [408, "fsync_nocancel", 408,  [A.FD] , { t:T.INT32, e:[] }],
    [409, "connect_nocancel", 409,  [A.SOCKFD,A.ADDR.copy("name"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [410, "sigsuspend_nocancel", 410,  [{ t:"sigset_t", n:"mask" }] , { t:T.INT32, e:[] }],
    [411, "readv_nocancel", 411,  [A.FD,{ t:"struct iovec", n:"*iovp" },{ t:T.UINT32, n:"iovcnt" }] , A.LEN.asReturn()],
    [412, "writev_nocancel", 412,  [A.FD,{ t:"struct iovec", n:"*iovp" },{ t:T.UINT32, n:"iovcnt" }] , A.LEN.asReturn()],
    [413, "sendto_nocancel", 413,  [A.SOCKFD,A.ADDR.copy("buf"),{ t:T.ULONG, n:"len" },{ t:T.INT32, n:"flags" },A.ADDR.copy("to"),A.SOCKLEN] , { t:T.INT32, e:[] }],
    [414, "pread_nocancel", 414,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.LEN.copy("nbyte"),{ t:"off_t", n:"offset" }] , A.LEN.asReturn()],
    [415, "pwrite_nocancel", 415,  [A.FD,A.OUTPUT_CHAR_BUFFER,A.LEN.copy("nbyte"),{ t:"off_t", n:"offset" }] , A.LEN.asReturn()],
    [416, "waitid_nocancel", 416,  [{ t:"idtype_t", n:"idtype" },{ t:"id_t", n:"id" },{ t:"siginfo_t", n:"*infop" },{ t:T.INT32, n:"options" }] , { t:T.INT32, e:[] }],
    [417, "poll_nocancel", 417,  [{ t:"struct pollfd", n:"*fds" },{ t:T.UINT32, n:"nfds" },{ t:T.INT32, n:"timeout" }] , { t:T.INT32, e:[] }],
    [418, "msgsnd_nocancel", 418,  [{ t:T.INT32, n:"msqid" },{ t:T.POINTER64, n:"*msgp" },{ t:T.ULONG, n:"msgsz" },{ t:T.INT32, n:"msgflg" }] , { t:T.INT32, e:[] }],
    [419, "msgrcv_nocancel", 419,  [{ t:T.INT32, n:"msqid" },{ t:T.POINTER64, n:"*msgp" },{ t:T.ULONG, n:"msgsz" },{ T:T.LONG, n:"msgtyp" },{ t:T.INT32, n:"msgflg" }] , A.LEN.asReturn()],
    [420, "sem_wait_nocancel", 420,  [{ t:"sem_t", n:"*sem" }] , { t:T.INT32, e:[] }],
    [421, "aio_suspend_nocancel", 421,  [{ t:"user_addr_t", n:"aiocblist" },{ t:T.INT32, n:"nent" },{ t:"user_addr_t", n:"timeoutp" }] , { t:T.INT32, e:[] }],
    [422, "__sigwait_nocancel", 422,  [{ t:"user_addr_t", n:"set" },{ t:"user_addr_t", n:"sig" }] , { t:T.INT32, e:[] }],
    [423, "__semwait_signal_nocancel", 423, [{ t:T.INT32, n:"cond_sem" } ,{ t:T.INT32, n:"mutex_sem" },{ t:T.INT32, n:"timeout" },{ t:T.INT32, n:"relative" },{ t:"int64_t", n:"tv_sec" },{ t:"int32_t", n:"tv_nsec" }], { t:T.INT32 e:[] }],
    [424, "__mac_mount", 424,  [{ T:T.CHAR, n:"*type" },{ T:T.CHAR, n:"*path" },{ t:T.INT32, n:"flags" },A.ADDR.copy("data"),{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [425, "__mac_get_mount", 425,  [{ T:T.CHAR, n:"*path" },{ t:"struct mac", n:"*mac_p" }] , { t:T.INT32, e:[] }],
    [426, "__mac_getfsstat", 426,  [A.OUTPUT_CHAR_BUFFER,{ t:T.INT32, n:"bufsize" },{ t:"user_addr_t", n:"mac" },{ t:T.INT32, n:"macsize" },{ t:T.INT32, n:"flags" }] , { t:T.INT32, e:[] }],
    [427, "fsgetpath", 427,  [A.OUTPUT_CHAR_BUFFER,{ t:T.ULONG, n:"bufsize" },{ t:"user_addr_t", n:"fsid" },{ t:"uint64_t", n:"objid" }] , A.LEN.asReturn()],  // [extra=private fsgetpath (File{ t:"Manager", n:"SPI" })]
    [428, "audit_session_self", 428,  [] , { t:"mach_port_name_t", e:[] }],
    [429, "audit_session_join", 429,  [{ t:"mach_port_name_t", n:"port" }] , { t:T.INT32, e:[] }],

];