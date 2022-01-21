import {InterruptorAgent} from "../common/InterruptorAgent";
import {InterruptorGenericException} from "../common/InterruptorException";
import {T} from "../common/DataTypes";
import {L} from "../common/DataLabels";
import {X} from "./LinuxArm64Flags";

const SVC_NUM = 0;
const SVC_NAME = 1;
const SVC_ARG = 3;
const SVC_RET = 4;
const SVC_ERR = 5;

const SVC = [
    [0,"io_setup",0x00,["unsigned nr_reqs","aio_context_t *ctx"]],
    [1,"io_destroy",0x01,["aio_context_t ctx"]],
    [2,"io_submit",0x02,["aio_context_t","long","struct iocb * *"]],
    [3,"io_cancel",0x03,["aio_context_t ctx_id","struct iocb *iocb","struct io_event *result"]],
    [4,"io_getevents",0x04,["aio_context_t ctx_id","long min_nr","long nr","struct io_event *events","struct __kernel_timespec *timeout"]],
    [5,"setxattr",0x05,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},
        {t:T.STRING, n:"name", c:true},
        {t:T.POINTER64, n:"value"},
        {t:T.UINT32, n:"size", l:L.SIZE},
        {t:T.INT32, n:"flags", l:L.FLAG, f:X.XATTR }]],
    [6,"lsetxattr",0x06,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},
        {t:T.STRING, n:"name", c:true},
        {t:T.POINTER64, n:"value", c:true},
        {t:T.UINT32, n:"size", l:L.SIZE},
        {t:T.INT32, n:"flags", l:L.FLAG, f:X.XATTR }]],
    [7,"fsetxattr",0x07,[{t:T.UINT32, n:"fd", l:L.FD},{t:T.STRING, n:"name", c:true},"const void *value","size_t size","int flags"]],
    [8,"getxattr",0x08,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},{t:T.STRING, n:"name", c:true},"void *value","size_t size"]],
    [9,"lgetxattr",0x09,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},{t:T.STRING, n:"name", c:true},"void *value","size_t size"]],
    [10,"fgetxattr",0x0a,[{t:T.UINT32, n:"fd", l:L.FD},{t:T.STRING, n:"name", c:true},"void *value","size_t size"]],
    [11,"listxattr",0x0b,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},"char *list","size_t size"]],
    [12,"llistxattr",0x0c,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},"char *list","size_t size"]],
    [13,"flistxattr",0x0d,[{t:T.UINT32, n:"fd", l:L.FD},"char *list","size_t size"]],
    [14,"removexattr",0x0e,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},{t:T.STRING, n:"name", c:true}]],
    [15,"lremovexattr",0x0f,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},{t:T.STRING, n:"name", c:true}]],
    [16,"fremovexattr",0x10,[{t:T.UINT32, n:"fd", l:L.FD},{t:T.STRING, n:"name", c:true}]],
    [17,"getcwd",0x11,["char *buf","unsigned long size"]],
    [18,"lookup_dcookie",0x12,["u64 cookie64","char *buf","size_t len"]],
    [19,"eventfd2",0x13,["unsigned int count","int flags"]],
    [20,"epoll_create1",0x14,["int flags"]],
    [21,"epoll_ctl",0x15,["int epfd","int op",{t:T.UINT32, n:"fd", l:L.FD},"struct epoll_event *event"]],
    [22,"epoll_pwait",0x16,["int epfd","struct epoll_event *events","int maxevents","int timeout","const sigset_t *sigmask","size_t sigsetsize"]],
    [23,"dup",0x17,["unsigned int fildes"]],
    [24,"dup3",0x18,["unsigned int oldfd","unsigned int newfd","int flags"]],
    [25,"fcntl",0x19,[{t:T.UINT32, n:"fd", l:L.FD},"unsigned int cmd","unsigned long arg"]],
    [26,"inotify_init1",0x1a,["int flags"]],
    [27,"inotify_add_watch",0x1b,[
        {t:T.UINT32, n:"fd", l:L.FD},
        {t:T.STRING, n:"path", l:L.PATH, c:true},"u32 mask"]],
    [28,"inotify_rm_watch",0x1c,[{t:T.UINT32, n:"fd", l:L.FD},"__s32 wd"]],
    [29,"ioctl",0x1d,[{t:T.UINT32, n:"fd", l:L.FD},"unsigned int cmd","unsigned long arg"]],
    [30,"ioprio_set",0x1e,["int which","int who","int ioprio"]],
    [31,"ioprio_get",0x1f,["int which","int who"]],
    [32,"flock",0x20,[{t:T.UINT32, n:"fd", l:L.FD},"unsigned int cmd"]],
    [33,"mknodat",0x21,["int dfd","const char * filename","umode_t mode","unsigned dev"]],
    [34,"mkdirat",0x22,["int dfd","const char * pathname","umode_t mode"]],
    [35,"unlinkat",0x23,["int dfd","const char * pathname","int flag"]],
    [36,"symlinkat",0x24,["const char * oldname","int newdfd","const char * newname"]],
    [37,"linkat",0x25,["int olddfd","const char *oldname","int newdfd","const char *newname","int flag"]],
    [38,"renameat",0x26,["int olddfd","const char * oldname","int newdfd","const char * newname"]],
    [39,"umount2",0x27,[
        {t:T.CHAR_BUFFER, n:"target", l:L.PATH, c:true},
        {t:T.INT32, n:"flags", l:L.FLAG, f:X.UMOUNT, c:true}]],
    [40,"mount",0x28,["char *dev_name","char *dir_name","char *type","unsigned long flags","void *dat"]],
    [41,"pivot_root",0x29,["const char *new_root","const char *put_old"]],
    [42,"nfsservctl",0x2a,["int cmd", "struct nfsctl_arg *argp","union nfsctl_res *resp"]],
    [43,"statfs",0x2b,["const char * path","struct statfs *buf"]],
    [44,"fstatfs",0x2c,[{t:T.UINT32, n:"fd", l:L.FD},"struct statfs *buf"]],
    [45,"truncate",0x2d,[
        {t:T.STRING, n:"path", l:L.PATH, c:true},"long length"]],
    [46,"ftruncate",0x2e,[{t:T.UINT32, n:"fd", l:L.FD},"unsigned long length"]],
    [47,"fallocate",0x2f,[{t:T.UINT32, n:"fd", l:L.FD},"int mode","loff_t offset","loff_t len"]],
    [48,"faccessat",0x30,["int dfd",{t:T.STRING, n:"filename", c:true},"int mode"]],
    [49,"chdir",0x31,[
        {t:T.CHAR_BUFFER, n:"path", l:L.PATH, c:true}]],
    [50,"fchdir",0x32,[
        {t:T.UINT32, n:"fd", l:L.FD, c:true}]],
    [51,"chroot",0x33,[
        {t:T.CHAR_BUFFER, n:"path", l:L.PATH, c:true}]],
    [52,"fchmod",0x34,[
        {t:T.UINT32, n:"fd", l:L.FD},
        {t:T.USHORT, n:"mode", l:L.ATTRMODE, f:X.ATTR}]],
    [53,"fchmodat",0x35,["int dfd",{t:T.STRING, n:"filename", c:true},"umode_t mode"]],
    [54,"fchownat",0x36,["int dfd",{t:T.STRING, n:"filename", c:true},"uid_t user","gid_t group","int fla"]],
    [55,"fchown",0x37,[{t:T.UINT32, n:"fd", l:L.FD},"uid_t user","gid_t group"]],
    [56,"openat",0x38,["int dfd",{t:T.STRING, n:"filename", c:true},"int flags","umode_t mode"],{t:T.UINT32, r:1, n:"FD", l:L.FD}],
    [57,"close",0x39,[{t:T.UINT32, n:"fd", l:L.FD}]],
    [58,"vhangup",0x3a,["-"]],
    [59,"pipe2",0x3b,["int *fildes","int flags"]],
    [60,"quotactl",0x3c,["unsigned int cmd","const char *special","qid_t id","void *addr"]],
    [61,"getdents64",0x3d,[{t:T.UINT32, n:"fd", l:L.FD},"struct linux_dirent64 *dirent","unsigned int count"]],
    [62,"lseek",0x3e,[
        {t:T.UINT32, n:"fd", l:L.FD},
        {t:T.UINT32, n:"offset"},
        {t:T.UINT32, n:"whence", l:L.SIZE}]],
    [63,"read",0x3f,[
        {t:T.UINT32, n:"fd", l:L.FD},
        {t:T.POINTER64, n:"buf", l:L.OUTPUT_BUFFER},
        {t:T.UINT32, n:"count", l:L.SIZE}
    ], {t:T.UINT32, r:1, n:"sz", l:L.SIZE}],
    [64,"write",0x40,[
        {t:T.UINT32, n:"fd", l:L.FD},
        {t:T.CHAR_BUFFER, n:"buf", c:true},
        {t:T.UINT32, n:"count", l:L.SIZE}]],
    [65,"readv",0x41,["unsigned long fd","const struct iovec *vec","unsigned long vlen"]],
    [66,"writev",0x42,["unsigned long fd","const struct iovec *vec","unsigned long vlen"]],
    [67,"pread64",0x43,[{t:T.UINT32, n:"fd", l:L.FD},"char *buf","size_t count","loff_t pos"]],
    [68,"pwrite64",0x44,[{t:T.UINT32, n:"fd", l:L.FD},"const char *buf","size_t count","loff_t pos"]],
    [69,"preadv",0x45,["unsigned long fd","const struct iovec *vec","unsigned long vlen","unsigned long pos_l","unsigned long pos_"]],
    [70,"pwritev",0x46,["unsigned long fd","const struct iovec *vec","unsigned long vlen","unsigned long pos_l","unsigned long pos_"]],
    [71,"sendfile",0x47,["int out_fd","int in_fd","off_t *offset","size_t count"]],
    [72,"pselect6",0x48,["int","fd_set *","fd_set *","fd_set *","struct __kernel_timespec *","void *["]],
    [73,"ppoll",0x49,["struct pollfd *","unsigned int","struct __kernel_timespec *","const sigset_t *","size_"]],
    [74,"signalfd4",0x4a,["int ufd","sigset_t *user_mask","size_t sizemask","int flags"]],
    [75,"vmsplice",0x4b,[{t:T.UINT32, n:"fd", l:L.FD},"const struct iovec *iov","unsigned long nr_segs","unsigned int flags"]],
    [76,"splice",0x4c,[{t:T.UINT32, n:"fd_in", l:L.FD},"loff_t *off_in",{t:T.UINT32, n:"fd_out", l:L.FD},"loff_t *off_out","size_t len","unsigned int flags["]],
    [77,"tee",0x4d,[{t:T.UINT32, n:"fd_in", l:L.FD},{t:T.UINT32, n:"fd_out", l:L.FD},"size_t len","unsigned int flags"]],
    [78,"readlinkat",0x4e,["int dfd",
        {t:T.STRING, n:"path", l:L.PATH, c:true},"char *buf","int bufsiz"]],
    [79,"newfstatat",0x4f,["int dfd",{t:T.STRING, n:"filename", c:true},"struct stat *statbuf","int flag"]],
    [80,"fstat",0x50,[{t:T.UINT32, n:"fd", l:L.FD},"struct __old_kernel_stat *statbuf"]],
    [81,"sync",0x51,[]],
    [82,"fsync",0x52,[{t:T.UINT32, n:"fd", l:L.FD}]],
    [83,"fdatasync",0x53,[{t:T.UINT32, n:"fd", l:L.FD}]],
    [84,"sync_file_range",0x54,[{t:T.UINT32, n:"fd", l:L.FD},"loff_t offset","loff_t nbytes","unsigned int flags"]],
    [85,"timerfd_create",0x55,["int clockid","int flags"]],
    [86,"timerfd_settime",0x56,["int ufd","int flags","const struct __kernel_itimerspec *utmr","struct __kernel_itimerspec *otmr"]],
    [87,"timerfd_gettime",0x57,["int ufd","struct __kernel_itimerspec *otmr"]],
    [88,"utimensat",0x58,["int dfd",{t:T.STRING, n:"filename", c:true},"struct __kernel_timespec *utimes","int flags"]],
    [89,"acct",0x59,[{t:T.STRING, n:"name", c:true}]],
    [90,"capget",0x5a,["cap_user_header_t header","cap_user_data_t dataptr"]],
    [91,"capset",0x5b,["cap_user_header_t header","const cap_user_data_t data"]],
    [92,"personality",0x5c,["unsigned int personality"]],
    [93,"exit",0x5d,["int error_code"]],
    [94,"exit_group",0x5e,["int error_code"]],
    [95,"waitid",0x5f,["int which","pid_t pid","struct siginfo *infop","int options","struct rusage *r"]],
    [96,"set_tid_address",0x60,["int *tidptr"]],
    [97,"unshare",0x61,["unsigned long unshare_flags"]],
    [98,"futex",0x62,["u32 *uaddr","int op","u32 val","struct __kernel_timespec *utime","u32 *uaddr2","u32 val3["]],
    [99,"set_robust_list",0x63,["struct robust_list_head *head","size_t len"]],
    [100,"get_robust_list",0x64,["int pid","struct robust_list_head * *head_ptr","size_t *len_ptr"]],
    [101,"nanosleep",0x65,["struct __kernel_timespec *rqtp","struct __kernel_timespec *rmtp"]],
    [102,"getitimer",0x66,["int which","struct itimerval *value"]],
    [103,"setitimer",0x67,["int which","struct itimerval *value","struct itimerval *ovalue"]],
    [104,"kexec_load",0x68,["unsigned long entry","unsigned long nr_segments","struct kexec_segment *segments","unsigned long flags"]],
    [105,"init_module",0x69,["void *umod","unsigned long len","const char *uargs"]],
    [106,"delete_module",0x6a,["const char *name_user","unsigned int flags"]],
    [107,"timer_create",0x6b,["clockid_t which_clock","struct sigevent *timer_event_spec","timer_t * created_timer_id"]],
    [108,"timer_gettime",0x6c,["timer_t timer_id","struct __kernel_itimerspec *setting"]],
    [109,"timer_getoverrun",0x6d,["timer_t timer_id"]],
    [110,"timer_settime",0x6e,["timer_t timer_id","int flags","const struct __kernel_itimerspec *new_setting","struct __kernel_itimerspec *old_setting"]],
    [111,"timer_delete",0x6f,["timer_t timer_id"]],
    [112,"clock_settime",0x70,["clockid_t which_clock","const struct __kernel_timespec *tp"]],
    [113,"clock_gettime",0x71,["clockid_t which_clock","struct __kernel_timespec *tp"]],
    [114,"clock_getres",0x72,["clockid_t which_clock","struct __kernel_timespec *tp"]],
    [115,"clock_nanosleep",0x73,["clockid_t which_clock","int flags","const struct __kernel_timespec *rqtp","struct __kernel_timespec *rmtp"]],
    [116,"syslog",0x74,["int type","char *buf","int len"]],
    [117,"ptrace",0x75,["long request","long pid","unsigned long addr","unsigned long data"]],
    [118,"sched_setparam",0x76,["pid_t pid","struct sched_param *param"]],
    [119,"sched_setscheduler",0x77,["pid_t pid","int policy","struct sched_param *param"]],
    [120,"sched_getscheduler",0x78,["pid_t pid"]],
    [121,"sched_getparam",0x79,["pid_t pid","struct sched_param *param"]],
    [122,"sched_setaffinity",0x7a,["pid_t pid","unsigned int len","unsigned long *user_mask_ptr"]],
    [123,"sched_getaffinity",0x7b,["pid_t pid","unsigned int len","unsigned long *user_mask_ptr"]],
    [124,"sched_yield",0x7c,["-"]],
    [125,"sched_get_priority_max",0x7d,["int policy"]],
    [126,"sched_get_priority_min",0x7e,["int policy"]],
    [127,"sched_rr_get_interval",0x7f,["pid_t pid","struct __kernel_timespec *interval"]],
    [128,"restart_syscall",0x80,["-"]],
    [129,"kill",0x81,["pid_t pid","int sig"]],
    [130,"tkill",0x82,["pid_t pid","int sig"]],
    [131,"tgkill",0x83,["pid_t tgid","pid_t pid","int sig"]],
    [132,"sigaltstack",0x84,["const struct sigaltstack *uss","struct sigaltstack *uoss"]],
    [133,"rt_sigsuspend",0x85,["sigset_t *unewset","size_t sigsetsize"]],
    [134,"rt_sigaction",0x86,["int","const struct sigaction *","struct sigaction *","size_t"]],
    [135,"rt_sigprocmask",0x87,["int how","sigset_t *set","sigset_t *oset","size_t sigsetsize"]],
    [136,"rt_sigpending",0x88,["sigset_t *set","size_t sigsetsize"]],
    [137,"rt_sigtimedwait",0x89,["const sigset_t *uthese","siginfo_t *uinfo","const struct __kernel_timespec *uts","size_t sigsetsize"]],
    [138,"rt_sigqueueinfo",0x8a,["pid_t pid","int sig","siginfo_t *uinfo"]],
    [139,"rt_sigreturn",0x8b,[]],
    [140,"setpriority",0x8c,["int which","int who","int niceval"]],
    [141,"getpriority",0x8d,["int which","int who"]],
    [142,"reboot",0x8e,["int magic1","int magic2","unsigned int cmd","void *arg"]],
    [143,"setregid",0x8f,["gid_t rgid","gid_t egid"]],
    [144,"setgid",0x90,["gid_t gid"]],
    [145,"setreuid",0x91,["uid_t ruid","uid_t euid"]],
    [146,"setuid",0x92,["uid_t uid"]],
    [147,"setresuid",0x93,["uid_t ruid","uid_t euid","uid_t suid"]],
    [148,"getresuid",0x94,["uid_t *ruid","uid_t *euid","uid_t *suid"]],
    [149,"setresgid",0x95,["gid_t rgid","gid_t egid","gid_t sgid"]],
    [150,"getresgid",0x96,["gid_t *rgid","gid_t *egid","gid_t *sgid"]],
    [151,"setfsuid",0x97,["uid_t uid"]],
    [152,"setfsgid",0x98,["gid_t gid"]],
    [153,"times",0x99,["struct tms *tbuf"]],
    [154,"setpgid",0x9a,["pid_t pid","pid_t pgid"]],
    [155,"getpgid",0x9b,["pid_t pid"]],
    [156,"getsid",0x9c,["pid_t pid"]],
    [157,"setsid",0x9d,["-"]],
    [158,"getgroups",0x9e,["int gidsetsize","gid_t *grouplist"]],
    [159,"setgroups",0x9f,["int gidsetsize","gid_t *grouplist"]],
    [160,"uname",0xa0,["struct old_utsname *"]],
    [161,"sethostname",0xa1,[
        {t:T.CHAR_BUFFER, n:"name"},
        {t:T.UINT32, n:"length"}]],
    [162,"setdomainname",0xa2,[
        {t:T.CHAR_BUFFER, n:"name"},
        {t:T.UINT32, n:"length"}]],
    [163,"getrlimit",0xa3,["unsigned int resource","struct rlimit *rlim"]],
    [164,"setrlimit",0xa4,["unsigned int resource","struct rlimit *rlim"]],
    [165,"getrusage",0xa5,["int who","struct rusage *ru"]],
    [166,"umask",0xa6,[
        {t:T.UINT32, n:"mask", l:L.ATTRMODE, f:X.ATTR}]],
    [167,"prctl",0xa7,["int option","unsigned long arg2","unsigned long arg3","unsigned long arg4","unsigned long arg5"]],
    [168,"getcpu",0xa8,["unsigned *cpu","unsigned *node","struct getcpu_cache *cache"]],
    [169,"gettimeofday",0xa9,["struct timeval *tv","struct timezone *tz"]],
    [170,"settimeofday",0xaa,["struct timeval *tv","struct timezone *tz"]],
    [171,"adjtimex",0xab,["struct __kernel_timex *txc_p"]],
    [172,"getpid",0xac,[]],
    [173,"getppid",0xad,[]],
    [174,"getuid",0xae,[]],
    [175,"geteuid",0xaf,[]],
    [176,"getgid",0xb0,[]],
    [177,"getegid",0xb1,[]],
    [178,"gettid",0xb2,[]],
    [179,"sysinfo",0xb3,["struct sysinfo *info"]],
    [180,"mq_open",0xb4,[{t:T.STRING, n:"name", c:true},"int oflag","umode_t mode","struct mq_attr *attr"]],
    [181,"mq_unlink",0xb5,[{t:T.STRING, n:"name", c:true}]],
    [182,"mq_timedsend",0xb6,["mqd_t mqdes","const char *msg_ptr","size_t msg_len","unsigned int msg_prio","const struct __kernel_timespec *abs_timeout"]],
    [183,"mq_timedreceive",0xb7,["mqd_t mqdes","char *msg_ptr","size_t msg_len","unsigned int *msg_prio","const struct __kernel_timespec *abs_timeout"]],
    [184,"mq_notify",0xb8,["mqd_t mqdes","const struct sigevent *notification"]],
    [185,"mq_getsetattr",0xb9,["mqd_t mqdes","const struct mq_attr *mqstat","struct mq_attr *omqstat"]],
    [186,"msgget",0xba,["key_t key","int msgflg"]],
    [187,"msgctl",0xbb,["int msqid","int cmd","struct msqid_ds *buf"]],
    [188,"msgrcv",0xbc,["int msqid","struct msgbuf *msgp","size_t msgsz","long msgtyp","int msgflg"]],
    [189,"msgsnd",0xbd,["int msqid","struct msgbuf *msgp","size_t msgsz","int msgflg"]],
    [190,"semget",0xbe,["key_t key","int nsems","int semflg"]],
    [191,"semctl",0xbf,["int semid","int semnum","int cmd","unsigned long arg"]],
    [192,"semtimedop",0xc0,["int semid","struct sembuf *sops","unsigned nsops","const struct __kernel_timespec *timeout"]],
    [193,"semop",0xc1,["int semid","struct sembuf *sops","unsigned nsops"]],
    [194,"shmget",0xc2,["key_t key","size_t size","int flag"]],
    [195,"shmctl",0xc3,["int shmid","int cmd","struct shmid_ds *buf"]],
    [196,"shmat",0xc4,["int shmid","char *shmaddr","int shmflg"]],
    [197,"shmdt",0xc5,["char *shmaddr"]],
    [198,"socket",0xc6,["int","int","int"]],
    [199,"socketpair",0xc7,["int","int","int","int *"]],
    [200,"bind",0xc8,["int","struct sockaddr *","int"]],
    [201,"listen",0xc9,["int","int"]],
    [202,"accept",0xca,["int","struct sockaddr *","int *"]],
    [203,"connect",0xcb,["int","struct sockaddr *","int"]],
    [204,"getsockname",0xcc,["int","struct sockaddr *","int *"]],
    [205,"getpeername",0xcd,["int","struct sockaddr *","int *"]],
    [206,"sendto",0xce,["int","void *","size_t","unsigned","struct sockaddr *","int"]],
    [207,"recvfrom",0xcf,["int","void *","size_t","unsigned","struct sockaddr *","int *"]],
    [208,"setsockopt",0xd0,[{t:T.UINT32, n:"fd", l:L.FD},"int level","int optname","char *optval","int optlen"]],
    [209,"getsockopt",0xd1,[{t:T.UINT32, n:"fd", l:L.FD},"int level","int optname","char *optval","int *optlen"]],
    [210,"shutdown",0xd2,["int","int"]],
    [211,"sendmsg",0xd3,[{t:T.UINT32, n:"fd", l:L.FD},"struct user_msghdr *msg","unsigned flags"]],
    [212,"recvmsg",0xd4,[{t:T.UINT32, n:"fd", l:L.FD},"struct user_msghdr *msg","unsigned flags"]],
    [213,"readahead",0xd5,[{t:T.UINT32, n:"fd", l:L.FD},"loff_t offset","size_t count"]],
    [214,"brk",0xd6,["unsigned long brk"]],
    [215,"munmap",0xd7,["unsigned long addr","size_t len"]],
    [216,"mremap",0xd8,["unsigned long addr","unsigned long old_len","unsigned long new_len","unsigned long flags","unsigned long new_addr"]],
    [217,"add_key",0xd9,["const char *_type","const char *_description","const void *_payload","size_t plen","key_serial_t destringid"]],
    [218,"request_key",0xda,["const char *_type","const char *_description","const char *_callout_info","key_serial_t destringid"]],
    [219,"keyctl",0xdb,["int cmd","unsigned long arg2","unsigned long arg3","unsigned long arg4","unsigned long arg5"]],
    [220,"clone",0xdc,["unsigned long","unsigned long","int *","int *","unsigned long"]],
    [221,"execve",0xdd,[{t:T.STRING, n:"filename", c:true},"const char *const *argv","const char *const *envp"]],
    [222,"mmap",0xde,[ {t:T.POINTER64, n:"addr", l:L.VADDR},
        {t:T.UINT32, n:"length", l:L.SIZE}, {t:T.INT32, n:"prot", l:L.FLAG, f:X.MPROT}, "int flags",
        {t:T.UINT32, n:"fd", l:L.FD, c:true}, {t:T.UINT32, n:"offset", l:L.SIZE}]],
    [223,"fadvise64",0xdf,[{t:T.UINT32, n:"fd", l:L.FD},"loff_t offset","size_t len","int advice"]],
    [224,"swapon",0xe0,["const char *specialfile","int swap_flags"]],
    [225,"swapoff",0xe1,["const char *specialfile"]],
    [226,"mprotect",0xe2,["unsigned long start","size_t len","unsigned long prot"]],
    [227,"msync",0xe3,["unsigned long start","size_t len","int flags"]],
    [228,"mlock",0xe4,["unsigned long start","size_t len"]],
    [229,"munlock",0xe5,["unsigned long start","size_t len"]],
    [230,"mlockall",0xe6,["int flags"]],
    [231,"munlockall",0xe7,[]],
    [232,"mincore",0xe8,["unsigned long start","size_t len","unsigned char * vec"]],
    [233,"madvise",0xe9,["unsigned long start","size_t len","int behavior"]],
    [234,"remap_file_pages",0xea,["unsigned long start","unsigned long size","unsigned long prot","unsigned long pgoff","unsigned long flags"]],
    [235,"mbind",0xeb,["unsigned long start","unsigned long len","unsigned long mode","const unsigned long *nmask","unsigned long maxnode","unsigned flags"]],
    [236,"get_mempolicy",0xec,["int *policy","unsigned long *nmask","unsigned long maxnode","unsigned long addr","unsigned long flags"]],
    [237,"set_mempolicy",0xed,["int mode","const unsigned long *nmask","unsigned long maxnode"]],
    [238,"migrate_pages",0xee,["pid_t pid","unsigned long maxnode","const unsigned long *from","const unsigned long *to"]],
    [239,"move_pages",0xef,["pid_t pid","unsigned long nr_pages","const void * *pages","const int *nodes","int *status","int flags"]],
    [240,"rt_tgsigqueueinfo",0xf0,["pid_t tgid","pid_t pid","int sig","siginfo_t *uinfo"]],
    [241,"perf_event_open",0xf1,["struct perf_event_attr *attr_uptr","pid_t pid","int cpu","int group_fd","unsigned long flags"]],
    [242,"accept4",0xf2,["int","struct sockaddr *","int *","int"]],
    [243,"recvmmsg",0xf3,[{t:T.UINT32, n:"fd", l:L.FD},"struct mmsghdr *msg","unsigned int vlen","unsigned flags","struct __kernel_timespec *timeout"]],
    [244,"not implemented",0xf4,[]],
    [245,"not implemented",0xf5,[]],
    [246,"not implemented",0xf6,[]],
    [247,"not implemented",0xf7,[]],
    [248,"not implemented",0xf8,[]],
    [249,"not implemented",0xf9,[]],
    [250,"not implemented",0xfa,[]],
    [251,"not implemented",0xfb,[]],
    [252,"not implemented",0xfc,[]],
    [253,"not implemented",0xfd,[]],
    [254,"not implemented",0xfe,[]],
    [255,"not implemented",0xff,[]],
    [256,"not implemented",0x100,[]],
    [257,"not implemented",0x101,[]],
    [258,"not implemented",0x102,[]],
    [259,"not implemented",0x103,[]],
    [260,"wait4",0x104,["pid_t pid","int *stat_addr","int options","struct rusage *ru"]],
    [261,"prlimit64",0x105,["pid_t pid","unsigned int resource","const struct rlimit64 *new_rlim","struct rlimit64 *old_rlim"]],
    [262,"fanotify_init",0x106,["unsigned int flags","unsigned int event_f_flags"]],
    [263,"fanotify_mark",0x107,["int fanotify_fd","unsigned int flags","u64 mask",{t:T.UINT32, n:"fd", l:L.FD},"const char *pathname"]],
    [264,"name_to_handle_at",0x108,["int dfd",{t:T.STRING, n:"name", c:true},"struct file_handle *handle","int *mnt_id","int flag"]],
    [265,"open_by_handle_at",0x109,["int mountdirfd","struct file_handle *handle","int flags"]],
    [266,"clock_adjtime",0x10a,["clockid_t which_clock","struct __kernel_timex *tx"]],
    [267,"syncfs",0x10b,[{t:T.UINT32, n:"fd", l:L.FD}]],
    [268,"setns",0x10c,[{t:T.UINT32, n:"fd", l:L.FD},"int nstype"]],
    [269,"sendmmsg",0x10d,[{t:T.UINT32, n:"fd", l:L.FD},"struct mmsghdr *msg","unsigned int vlen","unsigned flags"]],
    [270,"process_vm_readv",0x10e,["pid_t pid","const struct iovec *lvec","unsigned long liovcnt","const struct iovec *rvec","unsigned long riovcnt","unsigned long flags"]],
    [271,"process_vm_writev",0x10f,["pid_t pid","const struct iovec *lvec","unsigned long liovcnt","const struct iovec *rvec","unsigned long riovcnt","unsigned long flags"]],
    [272,"kcmp",0x110,["pid_t pid1","pid_t pid2","int type","unsigned long idx1","unsigned long idx2"]],
    [273,"finit_module",0x111,[{t:T.UINT32, n:"fd", l:L.FD},"const char *uargs","int flags"]],
    [274,"sched_setattr",0x112,["pid_t pid","struct sched_attr *attr","unsigned int flags"]],
    [275,"sched_getattr",0x113,["pid_t pid","struct sched_attr *attr","unsigned int size","unsigned int flags"]],
    [276,"renameat2",0x114,["int olddfd","const char *oldname","int newdfd","const char *newname","unsigned int flags"]],
    [277,"seccomp",0x115,["unsigned int op","unsigned int flags","void *uargs"]],
    [278,"getrandom",0x116,["char *buf","size_t count","unsigned int flags"]],
    [279,"memfd_create",0x117,["const char *uname_ptr","unsigned int flags"]],
    [280,"bpf",0x118,["int cmd","union bpf_attr *attr","unsigned int size"]],
    [281,"execveat",0x119,["int dfd",{t:T.STRING, n:"filename", c:true},"const char *const *argv","const char *const *envp","int flags"]],
    [282,"userfaultfd",0x11a,[
        {t:T.UINT32, n:"flags", l:L.FLAG, f:X.O_MODE }]],
    [283,"membarrier",0x11b,["int cmd","int flags"]],
    [284,"mlock2",0x11c,["unsigned long start","size_t len","int flags"]],
    [285,"copy_file_range",0x11d,[{t:T.UINT32, n:"fd_in", l:L.FD},"loff_t *off_in",{t:T.UINT32, n:"fd_out", l:L.FD},"loff_t *off_out","size_t len","unsigned int flags"]],
    [286,"preadv2",0x11e,["unsigned long fd","const struct iovec *vec","unsigned long vlen","unsigned long pos_l","unsigned long pos_h","rwf_t flags"]],
    [287,"pwritev2",0x11f,["unsigned long fd","const struct iovec *vec","unsigned long vlen","unsigned long pos_l","unsigned long pos_h","rwf_t flags"]],
    [288,"pkey_mprotect",0x120,["unsigned long start","size_t len","unsigned long prot","int pkey"]],
    [289,"pkey_alloc",0x121,["unsigned long flags","unsigned long init_val"]],
    [290,"pkey_free",0x122,["int pkey"]],
    [291,"statx",0x123,["int dfd",
        {t:T.STRING, n:"path", l:L.PATH, c:true},"unsigned flags","unsigned mask","struct statx *buffer"]]
    ];

const SVC_MAP_NUM:any = {};
const SVC_MAP_NAME:any = {};

SVC.map(x => {
    SVC_MAP_NAME[x[1] as string] = x;
    SVC_MAP_NUM[x[0] as string] = x;
});

export class LinuxArm64InterruptorAgent extends InterruptorAgent{

    filter_name: string[] = [];
    filter_num: string[] = [];
    svc_hk: any = {};
    hvc_hk: any = {};
    smc_hk: any = {};
    irq_hk: any = {};

    constructor(pConfig:any) {
        super(pConfig);
        this.configure(pConfig);
    }


    configure(pConfig:any){
        if(pConfig == null) return;

        for(let k in pConfig){
            switch (k){
                case 'svc':
                    for(let s in pConfig.svc) this.onSupervisorCall(s, pConfig.svc[s]);
                    break;
                case 'hvc':
                    for(let s in pConfig.hvc) this.onHypervisorCall((s as any).parseInt(16), pConfig.svc[s]);
                    break;
                case 'filter_name':
                    this.filter_name = pConfig.filter_name;
                    break;
                case 'filter_num':
                    this.filter_num = pConfig.filter_num;
                    break;
            }
        }

        this.exclude.svc = pConfig.exclude.hasOwnProperty("svc") ? pConfig.exclude.svc : [];
        this.exclude.hvc = pConfig.exclude.hasOwnProperty("hvc") ? pConfig.exclude.hvc : [];
        this.exclude.smc = pConfig.exclude.hasOwnProperty("smc") ? pConfig.exclude.smc : [];
        this.prepareExcludedSyscalls(this.exclude.syscalls);
        this.setupBuiltinHook();
    }

    /**
     * To generate the list of excluded syscall num from a list of syscall name
     * @param {string[]} pSyscalls An array of syscall name
     */
    prepareExcludedSyscalls( pSyscalls:string[] ):void {
        pSyscalls.map( svcName => {
            this.exclude.svc.push(SVC_MAP_NAME[svcName][0]);
        })
    }

    onSupervisorCall(pIntName:string, pHooks:any){
        const sc = SVC_MAP_NAME[pIntName];
        if(sc == null) throw InterruptorGenericException.UNKNOW_SYSCALL(pIntName);
        if(pHooks.hasOwnProperty('onEnter') || pHooks.hasOwnProperty('onLeave')){
            this.svc_hk[sc[0]] = pHooks
            console.log("[SVC HOOK] "+pIntName+" (int="+sc[0]+")");
        }

    }

    onHypervisorCall(pIntNum:number, pHooks:any){
        if(pHooks.hasOwnProperty('onEnter') || pHooks.hasOwnProperty('onLeave')){
            this.hvc_hk[pIntNum] = pHooks
        }

    }

    setupBuiltinHook(){
/*
        this.svc_hk[SVC_MAP_NAME.openat[0]] = {
            onLeave: function(ctx){
                if(ctx.dxcFD==null) ctx.dxcFD = {};
                ctx.dxcFD[ctx.x0.toInt32()+""] = ctx.dxcOpts;
            }
        }
*/
    }

    locatePC( pContext: any):string{
        let l = "";
        const r = Process.findRangeByAddress(pContext.pc);

        if(this.output.tid)
            l += `[TID=${Process.getCurrentThreadId()}]`;

        if(this.output.module){
            if(r != null){
                l =  `[${ r.file!=null ? r.file.path: '<no_path>'} +${pContext.pc.sub(r.base)}]`; ;
            }else{
                l = `[<unknow>  lr=${pContext.lr}]`;
            }
        }

        if(this.output.lr)
            l += `[lr=${pContext.lr}]`;

        return l;
    }

    startOnLoad( pModuleRegExp:RegExp, pCondition:any = null):any {
        let self=this, do_dlopen = null, call_ctor = null, match=null;
        Process.findModuleByName('linker64').enumerateSymbols().forEach(sym => {
            if (sym.name.indexOf('do_dlopen') >= 0) {
                do_dlopen = sym.address;
            } else if (sym.name.indexOf('call_constructor') >= 0) {
                call_ctor = sym.address;
            }
        });

        Interceptor.attach(do_dlopen, function (args) {
            const p = args[0].readUtf8String();

            if(p!=null && pModuleRegExp.exec(p) != null){
                console.log(p);
                match = p;
            }
        });

        Interceptor.attach(call_ctor, {
            onEnter:function () {
                if(match==null) return;

                if(pCondition!==null){
                    if(!(pCondition)(match, this)){
                        match = null;
                        return ;
                    }
                }

                console.warn("[INTERRUPTOR][STARTING] Module '"+match+"' is loading, tracer will start");
                match = null;
                self.start();

            }
        });



    }

    traceSyscall( pContext:any, pHookCfg:any = null){

        if(this.exclude.svc.indexOf(pContext.x8.toInt32())>-1) return;


        const sys = SVC_MAP_NUM[ pContext.x8.toInt32() ];
        var inst = "SVC";


        if(sys==null) {
            console.log( ' ['+this.locatePC(pContext.pc)+']   \x1b[35;01m' + inst + ' ('+pContext.x8+')\x1b[0m Syscall=<unknow>');
            return;
        }

        pContext.dxcRET = sys[SVC_RET];

        let s = "", p= "";
        pContext.dxcOpts = [];
        sys[3].map((vVal,vOff) => {
            const rVal = pContext["x"+vOff];
            if(typeof vVal === "string"){
                p += `${vVal} = ${rVal} , `;
            }else{
                p += `${vVal.n} = `;

                switch(vVal.l){
                    case L.FD:
                        p += `${rVal}  ${pContext.dxcFD[rVal.toInt32()+""]}  `;
                        break;
                    case L.FLAG:
                        p += `${(vVal.f)(rVal)}  `;
                        pContext.dxcOpts[vOff] = rVal;
                        break;
                    default:
                        switch(vVal.t){
                            case T.STRING:
                            case T.CHAR_BUFFER:
                                p += pContext.dxcOpts[vOff] = rVal.readUtf8String();
                                break;
                            case T.UINT32:
                            default:
                                p += pContext.dxcOpts[vOff] = rVal;
                                break;
                        }
                        break;
                }
                /*
                switch(vVal.t){
                    case T.STRING:
                    case T.CHAR_BUFFER:
                        p += pContext.dxcOpts[vOff] = rVal.readUtf8String();
                        break;
                    case T.UINT32:
                        pContext.dxcOpts[vOff] = rVal;
                        switch(vVal.l){
                            case L.FD:
                                p += `${rVal}  ${pContext.dxcFD[rVal.toInt32()+""]}  `;
                                break;
                            default:
                                p += rVal;
                                break;
                        }
                        break;
                    default:
                        p += pContext.dxcOpts[vOff] = rVal;
                        break;
                }*/
                p+= ' , ';
            }
        })
        s = `${sys[1]} ( ${p} ) `;




        if(this.output.flavor == InterruptorAgent.FLAVOR_DXC){
            pContext.log = this.locatePC(pContext)+'   \x1b[35;01m' + inst + ' :: '+pContext.x8+' \x1b[0m  '+s;
        }

    }


    traceSyscallRet( pContext:any, pHookCfg:any = null){


        if(this.exclude.svc.indexOf(pContext.x8.toInt32())>-1) return;

        let ret = pContext.dxcRET;
        if(ret != null){
            switch (ret.l) {
                case L.SIZE:
                    if(this.output.dump_buff)
                        ret = "(len="+pContext.x0+") "+pContext["x"+ret.r].readCString();
                    else
                        ret = pContext.x0;
                    break;
                case L.FD:
                    if(pContext.dxcFD==null) pContext.dxcFD = {};
                    pContext.dxcFD[ pContext.x0.toInt32()+""] = pContext.dxcOpts[ret.r];

                    ret = "(FD) "+pContext.x0;
                    break;
                default:
                    ret = pContext.x0;
                    break;
            }
        }else{
           ret = pContext.x0;
        }

        console.log( pContext.log +'   > '+ret);
    }


    trace( pStalkerInterator:any, pInstruction:any, pExtra:any):number{


        const self = this;

        let keep = 1;
        if(pExtra.onLeave == 1){

            pStalkerInterator.putCallout(function(context) {

                self.traceSyscallRet(context);

                const hook = self.svc_hk[context.x8.toInt32()];
                if(hook == null) return ;

                if(hook.onLeave != null){
                    (hook.onLeave)(context);
                }
            });

            pExtra.onLeave = null;
        }

        // debug
        //console.log("["+pInstruction.address+" : "+pInstruction.address.sub(pExtra.mod.__mod.base)+"] > "+Instruction.parse(pInstruction.address));

        if (pInstruction.mnemonic === 'svc') {

            //console.log("SVC Found : > "+pInstruction.mnemonic);
            pExtra.onLeave =  1;
            pStalkerInterator.putCallout(function(context) {

                if(context.dxcFD==null) context.dxcFD = {};
                const hook = self.svc_hk[context.x8.toInt32()];

                self.traceSyscall(context, hook);

                if(hook != null && hook.onEnter != null) (hook.onEnter)(context);
            });
        }

        return keep;
    }
}