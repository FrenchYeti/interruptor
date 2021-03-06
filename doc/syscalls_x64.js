import {L, T} from "../src/common/Types";

[0,"read",0x00,[A.FD,A.OUTPUT_CHAR_BUFFER,A.COUNT],RET.read],
[1,"write",0x01,[A.FD,{t:T.CHAR_BUFFER, n:"buf", c:true},A.COUNT],RET.write],
[2,"open",0x02,[A.CONST_FNAME,A.OFLAGS,A.OMODE],RET.open],
[3,"close",0x03,[A.FD],RET.close],
[4,"stat",0x04,[A.CONST_FNAME,A.STATBUF],RET.stat],
[5,"fstat",0x05,[A.FD,A.STATBUF],RET.fstat],
[6,"lstat",0x06,[A.CONST_FNAME,A.STATBUF],RET.lstat],
[7,"poll",0x07,["struct pollfd *ufds","unsigned int nfds","int timeout"],RET.poll],
[8,"lseek",0x08,[A.FD,A.OFFSET,{t:T.UINT32, n:"whence", l:L.FLAG, f:X.SEEK}],RET.lseek],
[9,"mmap",0x09,[A.START_ADDR,A.SIZE, A.MPROT, {t:T.INT32, n:"flags", l:L.FLAG, f:X.MAP}, {t:T.UINT32, n:"fd", l:L.MFD},A.OFFSET],RET.mmap],
[10,"mprotect",0x0a,[A.ADDR,A.SIZE,A.MPROT],RET.mprotect],
[11,"munmap",0x0b,[A.ADDR,A.SIZE],RET.munmap],
[12,"brk",0x0c,[A.ADDR.copy("*end_data_seg")],RET.brk],
[13,"rt_sigaction",0x0d,[A.SIG, A.SIGACTION.copy().constant(),A.SIGACTION,A.SIZE],RET.rt_sigaction],
[14,"rt_sigprocmask",0x0e,[{ t:T.INT32, n:"how", l:L.FLAG, f:X.SIG_FLAGS},"sigset_t *set","sigset_t *oset","size_t sigsetsize"],RET.rt_sigprocmask],
[15,"rt_sigreturn",0x0f,[],RET.rt_sigreturn],
[16,"ioctl",0x10,[A.FD,{t:T.UINT32, n:"cmd"},{t:T.ULONG, n:"arg"}],RET.ioctl],
[17,"pread64",0x11,[A.FD,A.OUTPUT_CHAR_BUFFER,A.COUNT,"loff_t pos"],RET.pread64],
[18,"pwrite64",0x12,[A.FD,"const char *buf",A.SIZE,A.OFFSET],RET.pwrite64],
[19,"readv",0x13,[A.LFD,A.IOVEC,A.SIZE.copy('iovcnt')],RET.readv],
[20,"writev",0x14,[A.LFD,A.IOVEC,A.SIZE.copy('iovcnt')],RET.writev],
[21,"access",0x15,[A.CONST_FNAME,"int mode"],RET.access],
[22,"pipe",0x16,[{t:T.POINTER64, n:"pipefd", l:L.PIPEFD}],RET.pipe],
[23,"select",0x17,["int n","fd_set *inp","fd_set *outp","fd_set *exp","struct timeval *tvp"],RET.select],
[24,"sched_yield",0x18,[],RET.sched_yield],
[25,"mremap",0x19,[A.ADDR,A.LEN.copy("old_len"),A.LEN.copy("new_len"),"unsigned long flags",A.START_ADDR.copy("new_addr")],RET.mremap],
[26,"msync",0x1a,[A.ADDR,A.SIZE,{t:T.INT32, n:"flags", l:L.FLAG, f:X.MS}],RET.msync],
[27,"mincore",0x1b,[A.ADDR,A.SIZE,"unsigned char * vec"],RET.mincore],
[28,"madvise",0x1c,[A.ADDR,A.SIZE, {t:T.INT32, n:"behavior", l:L.FLAG, f:X.MADV}],RET.madvise],
[29,"shmget",0x1d,["key_t key",A.SIZE,"int flag"],RET.shmget],
[30,"shmat",0x1e,["int shmid","char *shmaddr","int shmflg"],RET.shmat],
[31,"shmctl",0x1f,["int shmid","int cmd",A.SHMIDDS],RET.shmctl],
[32,"dup",0x20,[A.FD],{t:T.UINT32, n:"fd", l:L.FD, e:[E.EBADF, E.EBUSY, E.EINTR, E.EINVAL, E.EMFILE]}],
[33,"dup2",0x21,[A.FD.copy("oldfd"),A.FD.copy("newfd")],RET.dup2],
[34,"pause",0x22,[],RET.pause],
[35,"nanosleep",0x23,[A.KERNEL_TIMESPEC.copy("*rqtp"),A.KERNEL_TIMESPEC.copy("*rmtp")],RET.nanosleep],
[36,"getitimer",0x24,[A.TIMER,A.ITIMERVAL],RET.getitimer],
[37,"alarm",0x25,[{t:T.UINT32, n:"seconds"} ],RET.alarm],
[38,"setitimer",0x26,[A.TIMER,A.ITIMERVAL,A.ITIMERVAL.copy("*ovalue")],RET.setitimer],
[39,"getpid",0x27,[],RET.getpid],
[40,"sendfile",0x28,[A.FD.copy("out_fd"),A.FD.copy("in_fd"),A.OFFSET,A.SIZE],RET.sendfile],
[41,"socket",0x29,[{t:T.INT32, n:"domain", l:L.FLAG, f:X.PF},{t:T.INT32, n:"type", l:L.FLAG, f:X.SOCK},"int"],RET.socket],
[42,"connect",0x2a,[A.FD,A.SOCKADDR,"int"],RET.connect],
[43,"accept",0x2b,[A.SOCKFD,A.SOCKADDR,"int *"],RET.accept],
[44,"sendto",0x2c,[A.SOCKFD,"void *",A.SIZE,"unsigned",A.SOCKADDR,"int"],RET.sendto],
[45,"recvfrom",0x2d,[A.SOCKFD,"void *",A.SIZE,"unsigned",A.SOCKADDR,"int *"],RET.recvfrom],
[46,"sendmsg",0x2e,[A.SOCKFD,A.USR_MSGHDR,"unsigned flags"],RET.sendmsg],
[47,"recvmsg",0x2f,[A.SOCKFD,A.USR_MSGHDR,"unsigned flags"],RET.recvmsg],
[48,"shutdown",0x30,[A.SOCKFD,"int"],RET.shutdown],
[49,"bind",0x31,[A.SOCKFD,A.SOCKADDR,"int"],RET.bind],
[50,"listen",0x32,[A.SOCKFD,A.LEN],RET.listen],
[51,"getsockname",0x33,[A.SOCKFD,A.SOCKADDR,"int *"],RET.getsockname],
[52,"getpeername",0x34,[A.SOCKFD,A.SOCKADDR,"int *"],RET.getpeername],
[53,"socketpair",0x35,["int","int","int","int *"],RET.socketpair],
[54,"setsockopt",0x36,[A.SOCKFD,"int level","int optname","char *optval","int optlen"],RET.setsockopt],
[55,"getsockopt",0x37,[A.SOCKFD,"int level","int optname","char *optval","int *optlen"],RET.getsockopt],
[56,"clone",0x38,["unsigned long","unsigned long","int *","int *","unsigned long"],RET.clone],
[57,"fork",0x39,[],RET.fork],
[58,"vfork",0x3a,[],RET.vfork],
[59,"execve",0x3b,[ {t:T.STRING, n:"filename", c:true},{t:T.STRING, n:"*argv", c:true},{t:T.STRING, n:"*envp", c:true}],RET.execve],
[60,"exit",0x3c,[{ t:T.INT32, n:"status" }],RET.exit],
[61,"wait4",0x3d,[A.PID,"int *stat_addr","int options","struct rusage *ru"],RET.wait4],
[62,"kill",0x3e,[A.PID,"int sig"],RET.kill],
[63,"uname",0x3f,[{t:T.POINTER64, n:" *utsname" }],RET.uname],
[64,"semget",0x40,["key_t key",A.SIZE.copy("nsems"),"int semflg"],RET.semget],
[65,"semop",0x41,[A.SEMID,A.SEMBUF,"unsigned nsops"],RET.semop],
[66,"semctl",0x42,[A.SEMID,"int semnum","int cmd","unsigned long arg"],RET.semctl],
[67,"shmdt",0x43,["char *shmaddr"],RET.shmdt],
[68,"msgget",0x44,["key_t key","int msgflg"],RET.msgget],
[69,"msgsnd",0x45,[A.MQID,A.MSGBUF,A.SIZE.copy("msgsz"),{t:T.INT32, n:"msgflg", l:L.FLAG, f:X.MSGF}],RET.msgsnd],
[70,"msgrcv",0x46,[A.MQID,A.MSGBUF,A.SIZE.copy("msgsz"),"long msgtyp",{t:T.INT32, n:"msgflg", l:L.FLAG, f:X.MSGF}],RET.msgrcv],
[71,"msgctl",0x47,[A.MQID,{t:T.INT32, n:"cmd", l:L.FLAG, f:X.MSGCTL},  {t:T.POINTER64, n:"msqid_ds", l:L.DSTRUCT, f:"msqid_ds"}],RET.msgctl],
[72,"fcntl",0x48,[A.FD,{t:T.UINT32, n:"cmd", l:L.FLAG, f:X.FNCTL} ,{t:T.ULONG, n:"args", l:L.FLAG, r:"x1", f:X.FCNTL_ARGS}],RET.fcntl],
[73,"flock",0x49,[A.FD,{t:T.UINT32, n:"ope", l:L.FLAG, f:X.FLOCK}],RET.flock],
[74,"fsync",0x4a,[A.FD],RET.fsync],
[75,"fdatasync",0x4b,[A.FD],RET.fdatasync],
[76,"truncate",0x4c,[A.CONST_PATH, A.SIGNED_LEN],RET.truncate],
[77,"ftruncate",0x4d,[A.FD,A.LEN],RET.ftruncate],
[78,"getdents",0x4e,[{t:T.UINT32, n:"fd", l:L.FD},{t:T.POINTER64, n:"linux_dirent64 *dirent", l:L.DSTRUCT, f:"linux_dirent64"},A.SIZE],RET.getdents],
[79,"getcwd",0x4f,[A.OUTPUT_CHAR_BUFFER,A.SIZE],RET.getcwd],
[80,"chdir",0x50,[A.CONST_FNAME],RET.chdir],
[81,"fchdir",0x51,[A.FD],RET.fchdir],
[82,"rename",0x52,[A.CONST_FNAME.copy("old_name"),A.CONST_FNAME.copy("new_name")],RET.rename],
[83,"mkdir",0x53,[A.CONST_FNAME,A.XATTR.copy("umode")],RET.mkdir],
[84,"rmdir",0x54,[A.CONST_FNAME],RET.rmdir],
[85,"creat",0x55,[A.CONST_FNAME,"umode_t mode"],RET.creat],
[86,"link",0x56,[A.CONST_FNAME.copy("old_name"),A.CONST_FNAME.copy("new_name")],RET.link],
[87,"unlink",0x57,[A.CONST_FNAME],RET.unlink],
[88,"symlink",0x58,[A.CONST_FNAME.copy("old_name"),A.CONST_FNAME.copy("new_name")],RET.symlink],
[89,"readlink",0x59,[A.CONST_PATH,A.OUTPUT_CHAR_BUFFER,"int bufsiz"],RET.readlink],
[90,"chmod",0x5a,[A.CONST_FNAME,{t:T.USHORT, n:"mode", l:L.ATTRMODE, f:X.ATTR}],RET.chmod], //TODO : umode_t mode
[91,"fchmod",0x5b,[A.FD,{t:T.USHORT, n:"mode", l:L.ATTRMODE, f:X.ATTR}],RET.fchmod],
[92,"chown",0x5c,[A.CONST_FNAME,"uid_t user","gid_t group"],RET.chown],
[93,"fchown",0x5d,[A.FD,"uid_t user","gid_t group"],RET.fchown],
[94,"lchown",0x5e,[A.CONST_FNAME,"uid_t user","gid_t group"],RET.lchown],
[95,"umask",0x5f,["int mask"],RET.umask],
[96,"gettimeofday",0x60,["struct timeval *tv","struct timezone *tz"],RET.gettimeofday],
[97,"getrlimit",0x61,["unsigned int resource","struct rlimit *rlim"],RET.getrlimit],
[98,"getrusage",0x62,["int who","struct rusage *ru"],RET.getrusage],
[99,"sysinfo",0x63,["struct sysinfo *info"],RET.sysinfo],
[100,"times",0x64,["struct tms *tbuf"],RET.times],
[101,"ptrace",0x65,["long request","long pid",A.ADDR,"unsigned long data"],RET.ptrace],
[102,"getuid",0x66,[],RET.getuid],
[103,"syslog",0x67,["int type",A.OUTPUT_CHAR_BUFFER,"int len"],RET.syslog],
[104,"getgid",0x68,[],RET.getgid],
[105,"setuid",0x69,["uid_t uid"],RET.setuid],
[106,"setgid",0x6a,["gid_t gid"],RET.setgid],
[107,"geteuid",0x6b,[],RET.geteuid],
[108,"getegid",0x6c,[],RET.getegid],
[109,"setpgid",0x6d,[A.PID,"pid_t pgid"],RET.setpgid],
[110,"getppid",0x6e,[],RET.getppid],
[111,"getpgrp",0x6f,[],RET.getpgrp],
[112,"setsid",0x70,[],RET.setsid],
[113,"setreuid",0x71,["uid_t ruid","uid_t euid"],RET.setreuid],
[114,"setregid",0x72,["gid_t rgid","gid_t egid"],RET.setregid],
[115,"getgroups",0x73,["int gidsetsize","gid_t *grouplist"],RET.getgroups],
[116,"setgroups",0x74,["int gidsetsize","gid_t *grouplist"],RET.setgroups],
[117,"setresuid",0x75,["uid_t ruid","uid_t euid","uid_t suid"],RET.setresuid],
[118,"getresuid",0x76,["uid_t *ruid","uid_t *euid","uid_t *suid"],RET.getresuid],
[119,"setresgid",0x77,["gid_t rgid","gid_t egid","gid_t sgid"],RET.setresgid],
[120,"getresgid",0x78,["gid_t *rgid","gid_t *egid","gid_t *sgid"],RET.getresgid],
[121,"getpgid",0x79,[A.PID],RET.getpgid],
[122,"setfsuid",0x7a,["uid_t uid"],RET.setfsuid],
[123,"setfsgid",0x7b,["gid_t gid"],RET.setfsgid],
[124,"getsid",0x7c,[A.PID],RET.getsid],
[125,"capget",0x7d,["cap_user_header_t header","cap_user_data_t dataptr"],RET.capget],
[126,"capset",0x7e,["cap_user_header_t header","const cap_user_data_t data"],RET.capset],
[127,"rt_sigpending",0x7f,["sigset_t *set","size_t sigsetsize"],RET.rt_sigpending],
[128,"rt_sigtimedwait",0x80,["const sigset_t *uthese","siginfo_t *uinfo","const struct __kernel_timespec *uts","size_t sigsetsize"],RET.rt_sigtimedwait],
[129,"rt_sigqueueinfo",0x81,[A.PID,"int sig","siginfo_t *uinfo"],RET.rt_sigqueueinfo],
[130,"rt_sigsuspend",0x82,["sigset_t *unewset","size_t sigsetsize"],RET.rt_sigsuspend],
[131,"sigaltstack",0x83,["const struct sigaltstack *uss","struct sigaltstack *uoss"],RET.sigaltstack],
[132,"utime",0x84,["char *filename","struct utimbuf *times"],RET.utime],
[133,"mknod",0x85,[A.CONST_FNAME,"umode_t mode","unsigned dev"],RET.mknod],
[134,"uselib",0x86,["const char *library"],RET.uselib],
[135,"personality",0x87,["unsigned int personality"],RET.personality],
[136,"ustat",0x88,["unsigned dev","struct ustat *ubuf"],RET.ustat],
[137,"statfs",0x89,["const char * path","struct statfs *buf"],RET.statfs],
[138,"fstatfs",0x8a,[A.FD,"struct statfs *buf"],RET.fstatfs],
[139,"sysfs",0x8b,["int option","unsigned long arg1","unsigned long arg2",""],RET.sysfs],
[140,"getpriority",0x8c,["int which","int who"],RET.getpriority],
[141,"setpriority",0x8d,["int which","int who","int niceval"],RET.setpriority],
[142,"sched_setparam",0x8e,[A.PID,"struct sched_param *param"],RET.sched_setparam],
[143,"sched_getparam",0x8f,[A.PID,"struct sched_param *param"],RET.sched_getparam],
[144,"sched_setscheduler",0x90,[A.PID,"int policy","struct sched_param *param"],RET.sched_setscheduler],
[145,"sched_getscheduler",0x91,[A.PID],RET.sched_getscheduler],
[146,"sched_get_priority_max",0x92,["int policy"],RET.sched_get_priority_max],
[147,"sched_get_priority_min",0x93,["int policy"],RET.sched_get_priority_min],
[148,"sched_rr_get_interval",0x94,[A.PID,"struct __kernel_timespec *interval"],RET.sched_rr_get_interval],
[149,"mlock",0x95,[A.ADDR,A.SIZE],RET.mlock],
[150,"munlock",0x96,[A.ADDR,A.SIZE],RET.munlock],
[151,"mlockall",0x97,["int flags"],RET.mlockall],
[152,"munlockall",0x98,[],RET.munlockall],
[153,"vhangup",0x99,[],RET.vhangup],
[154,"modify_ldt",0x9a,[],RET.modify_ldt],
[155,"pivot_root",0x9b,["const char *new_root","const char *put_old"],RET.pivot_root],
[156,"_sysctl",0x9c,[],RET._sysctl],
[157,"prctl",0x9d,["int option","unsigned long arg2","unsigned long arg3","unsigned long arg4","unsigned long arg5",""],RET.prctl],
[158,"arch_prctl",0x9e,[],RET.arch_prctl],
[159,"adjtimex",0x9f,["struct __kernel_timex *txc_p"],RET.adjtimex],
[160,"setrlimit",0xa0,["unsigned int resource","struct rlimit *rlim"],RET.setrlimit],
[161,"chroot",0xa1,[A.CONST_FNAME],RET.chroot],
[162,"sync",0xa2,[],RET.sync],
[163,"acct",0xa3,[A.CONST_NAME],RET.acct],
[164,"settimeofday",0xa4,["struct timeval *tv","struct timezone *tz"],RET.settimeofday],
[165,"mount",0xa5,["char *dev_name","char *dir_name","char *type","unsigned long flags","void *data"],RET.mount],
[166,"umount2",0xa6,[],RET.umount2],
[167,"swapon",0xa7,[A.CONST_FNAME,"int swap_flags"],RET.swapon],
[168,"swapoff",0xa8,[A.CONST_FNAME],RET.swapoff],
[169,"reboot",0xa9,["int magic1","int magic2","unsigned int cmd","void *arg"],RET.reboot],
[170,"sethostname",0xaa,["char *name","int len"],RET.sethostname],
[171,"setdomainname",0xab,["char *name","int len"],RET.setdomainname],
[172,"iopl",0xac,[],RET.iopl],
[173,"ioperm",0xad,["unsigned long from","unsigned long num","int on"],RET.ioperm],
[174,"create_module",0xae,[],RET.create_module],
[175,"init_module",0xaf,["void *umod",A.LEN,"const char *uargs"],RET.init_module],
[176,"delete_module",0xb0,["const char *name_user","unsigned int flags"],RET.delete_module],
[177,"get_kernel_syms",0xb1,[],RET.get_kernel_syms],
[178,"query_module",0xb2,[],RET.query_module],
[179,"quotactl",0xb3,["unsigned int cmd","const char *special","qid_t id","void *addr"],RET.quotactl],
[180,"nfsservctl",0xb4,[],RET.nfsservctl],
[181,"getpmsg",0xb5,[],RET.getpmsg],
[182,"putpmsg",0xb6,[],RET.putpmsg],
[183,"afs_syscall",0xb7,[],RET.afs_syscall],
[184,"tuxcall",0xb8,[],RET.tuxcall],
[185,"security",0xb9,[],RET.security],
[186,"gettid",0xba,[],RET.gettid],
[187,"readahead",0xbb,[A.FD,"loff_t offset",A.COUNT],RET.readahead],
[188,"setxattr",0xbc,[A.CONST_PATH,A.CONST_NAME,"const void *value",A.SIZE,"int flags"],RET.setxattr],
[189,"lsetxattr",0xbd,[A.CONST_PATH,A.CONST_NAME,"const void *value",A.SIZE,"int flags"],RET.lsetxattr],
[190,"fsetxattr",0xbe,[A.FD,A.CONST_NAME,"const void *value",A.SIZE,"int flags"],RET.fsetxattr],
[191,"getxattr",0xbf,[A.CONST_PATH,A.CONST_NAME,A.PTR,A.SIZE],RET.getxattr],
[192,"lgetxattr",0xc0,[A.CONST_PATH,A.CONST_NAME,A.PTR,A.SIZE],RET.lgetxattr],
[193,"fgetxattr",0xc1,[A.FD,A.CONST_NAME,A.PTR,A.SIZE],RET.fgetxattr],
[194,"listxattr",0xc2,[A.CONST_PATH,"char *list",A.SIZE],RET.listxattr],
[195,"llistxattr",0xc3,[A.CONST_PATH,"char *list",A.SIZE],RET.llistxattr],
[196,"flistxattr",0xc4,[A.FD,"char *list",A.SIZE],RET.flistxattr],
[197,"removexattr",0xc5,[A.CONST_PATH,A.CONST_NAME],RET.removexattr],
[198,"lremovexattr",0xc6,[A.CONST_PATH,A.CONST_NAME],RET.lremovexattr],
[199,"fremovexattr",0xc7,[A.FD,A.CONST_NAME],RET.fremovexattr],
[200,"tkill",0xc8,[A.PID,"int sig"],RET.tkill],
[201,"time",0xc9,["time_t *tloc"],RET.time],
[202,"futex",0xca,["u32 *uaddr","int op","u32 val","struct __kernel_timespec *utime","u32 *uaddr2","u32 val3"],RET.futex],
[203,"sched_setaffinity",0xcb,[A.PID,"unsigned int len","unsigned long *user_mask_ptr"],RET.sched_setaffinity],
[204,"sched_getaffinity",0xcc,[A.PID,"unsigned int len","unsigned long *user_mask_ptr"],RET.sched_getaffinity],
[205,"set_thread_area",0xcd,[],RET.set_thread_area],
[206,"io_setup",0xce,["unsigned nr_reqs","aio_context_t *ctx"],RET.io_setup],
[207,"io_destroy",0xcf,["aio_context_t ctx"],RET.io_destroy],
[208,"io_getevents",0xd0,["aio_context_t ctx_id","long min_nr","long nr","struct io_event *events","struct __kernel_timespec *timeout"],RET.io_getevents],
[209,"io_submit",0xd1,["aio_context_t","long","struct iocb * *"],RET.io_submit],
[210,"io_cancel",0xd2,["aio_context_t ctx_id","struct iocb *iocb","struct io_event *result"],RET.io_cancel],
[211,"get_thread_area",0xd3,[],RET.get_thread_area],
[212,"lookup_dcookie",0xd4,["u64 cookie64",A.OUTPUT_CHAR_BUFFER,A.SIZE],RET.lookup_dcookie],
[213,"epoll_create",0xd5,["int size"],RET.epoll_create],
[214,"epoll_ctl_old",0xd6,[],RET.epoll_ctl_old],
[215,"epoll_wait_old",0xd7,[],RET.epoll_wait_old],
[216,"remap_file_pages",0xd8,[A.ADDR,"unsigned long size","unsigned long prot","unsigned long pgoff","unsigned long flags"],RET.remap_file_pages],
[217,"getdents64",0xd9,[A.FD,"struct linux_dirent64 *dirent","unsigned int count"],RET.getdents64],
[218,"set_tid_address",0xda,["int *tidptr"],RET.set_tid_address],
[219,"restart_syscall",0xdb,[],RET.restart_syscall],
[220,"semtimedop",0xdc,[A.SEMID,A.SEMBUF,"unsigned nsops","const struct __kernel_timespec *timeout"],RET.semtimedop],
[221,"fadvise64",0xdd,[A.FD,"loff_t offset",A.SIZE,"int advice"],RET.fadvise64],
[222,"timer_create",0xde,["clockid_t which_clock","struct sigevent *timer_event_spec","timer_t * created_timer_id"],RET.timer_create],
[223,"timer_settime",0xdf,["timer_t timer_id","int flags","const struct __kernel_itimerspec *new_setting","struct __kernel_itimerspec *old_setting"],RET.timer_settime],
[224,"timer_gettime",0xe0,["timer_t timer_id","struct __kernel_itimerspec *setting"],RET.timer_gettime],
[225,"timer_getoverrun",0xe1,["timer_t timer_id"],RET.timer_getoverrun],
[226,"timer_delete",0xe2,["timer_t timer_id"],RET.timer_delete],
[227,"clock_settime",0xe3,["clockid_t which_clock","const struct __kernel_timespec *tp"],RET.clock_settime],
[228,"clock_gettime",0xe4,["clockid_t which_clock","struct __kernel_timespec *tp"],RET.clock_gettime],
[229,"clock_getres",0xe5,["clockid_t which_clock","struct __kernel_timespec *tp"],RET.clock_getres],
[230,"clock_nanosleep",0xe6,["clockid_t which_clock","int flags","const struct __kernel_timespec *rqtp","struct __kernel_timespec *rmtp"],RET.clock_nanosleep],
[231,"exit_group",0xe7,["int error_code"],RET.exit_group],
[232,"epoll_wait",0xe8,["int epfd","struct epoll_event *events","int maxevents","int timeout"],RET.epoll_wait],
[233,"epoll_ctl",0xe9,["int epfd","int op",A.FD,"struct epoll_event *event"],RET.epoll_ctl],
[234,"tgkill",0xea,["pid_t tgid",A.PID,"int sig"],RET.tgkill],
[235,"utimes",0xeb,["char *filename","struct timeval *utimes"],RET.utimes],
[236,"vserver",0xec,[],RET.vserver],
[237,"mbind",0xed,[A.ADDR,A.LEN,"unsigned long mode","const unsigned long *nmask","unsigned long maxnode","unsigned flags"],RET.mbind],
[238,"set_mempolicy",0xee,["int mode","const unsigned long *nmask","unsigned long maxnode"],RET.set_mempolicy],
[239,"get_mempolicy",0xef,["int *policy","unsigned long *nmask","unsigned long maxnode",A.ADDR,"unsigned long flags"],RET.get_mempolicy],
[240,"mq_open",0xf0,[A.CONST_NAME,"int oflag","umode_t mode","struct mq_attr *attr"],RET.mq_open],
[241,"mq_unlink",0xf1,[A.CONST_NAME],RET.mq_unlink],
[242,"mq_timedsend",0xf2,["mqd_t mqdes","const char *msg_ptr","size_t msg_len","unsigned int msg_prio","const struct __kernel_timespec *abs_timeout"],RET.mq_timedsend],
[243,"mq_timedreceive",0xf3,["mqd_t mqdes","char *msg_ptr","size_t msg_len","unsigned int *msg_prio","const struct __kernel_timespec *abs_timeout"],RET.mq_timedreceive],
[244,"mq_notify",0xf4,["mqd_t mqdes","const struct sigevent *notification"],RET.mq_notify],
[245,"mq_getsetattr",0xf5,["mqd_t mqdes","const struct mq_attr *mqstat","struct mq_attr *omqstat"],RET.mq_getsetattr],
[246,"kexec_load",0xf6,["unsigned long entry","unsigned long nr_segments","struct kexec_segment *segments","unsigned long flags"],RET.kexec_load],
[247,"waitid",0xf7,["int which",A.PID,"struct siginfo *infop","int options","struct rusage *ru"],RET.waitid],
[248,"add_key",0xf8,["const char *_type","const char *_description","const void *_payload","size_t plen","key_serial_t destringid"],RET.add_key],
[249,"request_key",0xf9,["const char *_type","const char *_description","const char *_callout_info","key_serial_t destringid"],RET.request_key],
[250,"keyctl",0xfa,["int cmd","unsigned long arg2","unsigned long arg3","unsigned long arg4","unsigned long arg5",""],RET.keyctl],
[251,"ioprio_set",0xfb,["int which","int who","int ioprio"],RET.ioprio_set],
[252,"ioprio_get",0xfc,["int which","int who"],RET.ioprio_get],
[253,"inotify_init",0xfd,[],RET.inotify_init],
[254,"inotify_add_watch",0xfe,[A.FD,A.CONST_PATH,"u32 mask"],RET.inotify_add_watch],
[255,"inotify_rm_watch",0xff,[A.FD,"__s32 wd"],RET.inotify_rm_watch],
[256,"migrate_pages",0x100,[A.PID,"unsigned long maxnode","const unsigned long *from","const unsigned long *to"],RET.migrate_pages],
[257,"openat",0x101,[A.DFD,A.CONST_FNAME,"int flags","umode_t mode"],RET.openat],
[258,"mkdirat",0x102,[A.DFD,"const char * pathname","umode_t mode"],RET.mkdirat],
[259,"mknodat",0x103,[A.DFD,"const char * filename","umode_t mode","unsigned dev"],RET.mknodat],
[260,"fchownat",0x104,[A.DFD,A.CONST_FNAME,"uid_t user","gid_t group","int flag"],RET.fchownat],
[261,"futimesat",0x105,[A.DFD,A.CONST_FNAME,"struct timeval *utimes"],RET.futimesat],
[262,"newfstatat",0x106,[A.DFD,A.CONST_FNAME,"struct stat *statbuf","int flag"],RET.newfstatat],
[263,"unlinkat",0x107,[A.DFD,"const char * pathname","int flag"],RET.unlinkat],
[264,"renameat",0x108,["int olddfd","const char * oldname","int newdfd","const char * newname"],RET.renameat],
[265,"linkat",0x109,["int olddfd","const char *oldname","int newdfd","const char *newname","int flags"],RET.linkat],
[266,"symlinkat",0x10a,["const char * oldname","int newdfd","const char * newname"],RET.symlinkat],
[267,"readlinkat",0x10b,[A.DFD,A.CONST_PATH,A.OUTPUT_CHAR_BUFFER,"int bufsiz"],RET.readlinkat],
[268,"fchmodat",0x10c,[A.DFD,"const char * filename","umode_t mode"],RET.fchmodat],
[269,"faccessat",0x10d,[A.DFD,A.CONST_FNAME,"int mode"],RET.faccessat],
[270,"pselect6",0x10e,["int","fd_set *","fd_set *","fd_set *","struct __kernel_timespec *","void *"],RET.pselect6],
[271,"ppoll",0x10f,["struct pollfd *","unsigned int","struct __kernel_timespec *","const sigset_t *",A.SIZE],RET.ppoll],
[272,"unshare",0x110,["unsigned long unshare_flags"],RET.unshare],
[273,"set_robust_list",0x111,["struct robust_list_head *head",A.SIZE],RET.set_robust_list],
[274,"get_robust_list",0x112,[A.PID,"struct robust_list_head * *head_ptr","size_t *len_ptr"],RET.get_robust_list],
[275,"splice",0x113,["int fd_in","loff_t *off_in","int fd_out","loff_t *off_out",A.SIZE,"unsigned int flags"],RET.splice],
[276,"tee",0x114,["int fdin","int fdout",A.SIZE,"unsigned int flags"],RET.tee],
[277,"sync_file_range",0x115,[A.FD,"loff_t offset","loff_t nbytes","unsigned int flags"],RET.sync_file_range],
[278,"vmsplice",0x116,[A.FD,"const struct iovec *iov","unsigned long nr_segs","unsigned int flags"],RET.vmsplice],
[279,"move_pages",0x117,[A.PID,"unsigned long nr_pages","const void * *pages","const int *nodes","int *status","int flags"],RET.move_pages],
[280,"utimensat",0x118,[A.DFD,A.CONST_FNAME,"struct __kernel_timespec *utimes","int flags"],RET.utimensat],
[281,"epoll_pwait",0x119,["int epfd","struct epoll_event *events","int maxevents","int timeout","const sigset_t *sigmask","size_t sigsetsize"],RET.epoll_pwait],
[282,"signalfd",0x11a,["int ufd","sigset_t *user_mask","size_t sizemask"],RET.signalfd],
[283,"timerfd_create",0x11b,["int clockid","int flags"],RET.timerfd_create],
[284,"eventfd",0x11c,["unsigned int count"],RET.eventfd],
[285,"fallocate",0x11d,[A.FD,"int mode","loff_t offset","loff_t len"],RET.fallocate],
[286,"timerfd_settime",0x11e,["int ufd","int flags","const struct __kernel_itimerspec *utmr","struct __kernel_itimerspec *otmr"],RET.timerfd_settime],
[287,"timerfd_gettime",0x11f,["int ufd","struct __kernel_itimerspec *otmr"],RET.timerfd_gettime],
[288,"accept4",0x120,["int",A.SOCKADDR,"int *","int"],RET.accept4],
[289,"signalfd4",0x121,["int ufd","sigset_t *user_mask","size_t sizemask","int flags"],RET.signalfd4],
[290,"eventfd2",0x122,["unsigned int count","int flags"],RET.eventfd2],
[291,"epoll_create1",0x123,["int flags"],RET.epoll_create1],
[292,"dup3",0x124,["unsigned int oldfd","unsigned int newfd","int flags"],RET.dup3],
[293,"pipe2",0x125,[{t:T.POINTER64, n:"pipefd", l:L.PIPEFD},{t:T.INT32, n:"flags", l:L.FLAG, f:X.PIPE_FLAG}],RET.pipe2],
[294,"inotify_init1",0x126,["int flags"],RET.inotify_init1],
[295,"preadv",0x127,[A.LFD,A.IOVEC,A.SIZE.copy('iovcnt'),"unsigned long pos_l","unsigned long pos_h"],RET.preadv],
[296,"pwritev",0x128,[A.LFD,A.IOVEC,A.SIZE.copy('iovcnt'),"unsigned long pos_l","unsigned long pos_h"],RET.pwritev],
[297,"rt_tgsigqueueinfo",0x129,["pid_t tgid",A.PID,"int sig","siginfo_t *uinfo"],RET.rt_tgsigqueueinfo],
[298,"perf_event_open",0x12a,["struct perf_event_attr *attr_uptr",A.PID,"int cpu","int group_fd","unsigned long flags"],RET.perf_event_open],
[299,"recvmmsg",0x12b,[A.FD,"struct mmsghdr *msg","unsigned int vlen","unsigned flags","struct __kernel_timespec *timeout"],RET.recvmmsg],
[300,"fanotify_init",0x12c,["unsigned int flags","unsigned int event_f_flags"],RET.fanotify_init],
[301,"fanotify_mark",0x12d,["int fanotify_fd","unsigned int flags","u64 mask",A.FD,A.CONST_FNAME],RET.fanotify_mark],
[302,"prlimit64",0x12e,[A.PID,"unsigned int resource","const struct rlimit64 *new_rlim","struct rlimit64 *old_rlim"],RET.prlimit64],
[303,"name_to_handle_at",0x12f,[A.DFD,A.CONST_NAME,"struct file_handle *handle","int *mnt_id","int flag"],RET.name_to_handle_at],
[304,"open_by_handle_at",0x130,["int mountdirfd","struct file_handle *handle","int flags"],RET.open_by_handle_at],
[305,"clock_adjtime",0x131,["clockid_t which_clock","struct __kernel_timex *tx"],RET.clock_adjtime],
[306,"syncfs",0x132,[A.FD],RET.syncfs],
[307,"sendmmsg",0x133,[A.FD,"struct mmsghdr *msg","unsigned int vlen","unsigned flags"],RET.sendmmsg],
[308,"setns",0x134,[A.FD,"int nstype"],RET.setns],
[309,"getcpu",0x135,["unsigned *cpu","unsigned *node","struct getcpu_cache *cache"],RET.getcpu],
[310,"process_vm_readv",0x136,[A.PID,"const struct iovec *lvec","unsigned long liovcnt","const struct iovec *rvec","unsigned long riovcnt","unsigned long flags"],RET.process_vm_readv],
[311,"process_vm_writev",0x137,[A.PID,"const struct iovec *lvec","unsigned long liovcnt","const struct iovec *rvec","unsigned long riovcnt","unsigned long flags"],RET.process_vm_writev],
[312,"kcmp",0x138,["pid_t pid1","pid_t pid2","int type","unsigned long idx1","unsigned long idx2",""],RET.kcmp],
[313,"finit_module",0x139,[A.FD,"const char *uargs","int flags"],RET.finit_module],
[314,"sched_setattr",0x13a,[A.PID,"struct sched_attr *attr","unsigned int flags"],RET.sched_setattr],
[315,"sched_getattr",0x13b,[A.PID,"struct sched_attr *attr","unsigned int size","unsigned int flags"],RET.sched_getattr],
[316,"renameat2",0x13c,["int olddfd","const char *oldname","int newdfd","const char *newname","unsigned int flags"],RET.renameat2],
[317,"seccomp",0x13d,["unsigned int op","unsigned int flags","void *uargs"],RET.seccomp],
[318,"getrandom",0x13e,[A.OUTPUT_CHAR_BUFFER,A.COUNT,"unsigned int flags"],RET.getrandom],
[319,"memfd_create",0x13f,["const char *uname_ptr","unsigned int flags"],RET.memfd_create],
[320,"kexec_file_load",0x140,["int kernel_fd","int initrd_fd","unsigned long cmdline_len","const char *cmdline_ptr","unsigned long flags"],RET.kexec_file_load],
[321,"bpf",0x141,["int cmd","union bpf_attr *attr","unsigned int size"],RET.bpf],
[322,"execveat",0x142,[A.DFD,A.CONST_FNAME,"const char *const *argv","const char *const *envp","int flags"],RET.execveat],
[323,"userfaultfd",0x143,["int flags"],RET.userfaultfd],
[324,"membarrier",0x144,["int cmd","int flags"],RET.membarrier],
[325,"mlock2",0x145,[A.ADDR,A.SIZE,"int flags"],RET.mlock2],
[326,"copy_file_range",0x146,["int fd_in","loff_t *off_in","int fd_out","loff_t *off_out",A.SIZE,"unsigned int flags"],RET.copy_file_range],
[327,"preadv2",0x147,[A.LFD,A.IOVEC,A.SIZE.copy('iovcnt'),"unsigned long pos_l","unsigned long pos_h","rwf_t flags"],RET.preadv2],
[328,"pwritev2",0x148,[A.LFD,A.IOVEC,A.SIZE.copy('iovcnt'),"unsigned long pos_l","unsigned long pos_h","rwf_t flags"],RET.pwritev2],
[329,"pkey_mprotect",0x149,[A.ADDR,A.SIZE,"unsigned long prot","int pkey"],RET.pkey_mprotect],
[330,"pkey_alloc",0x14a,["unsigned long flags","unsigned long init_val"],RET.pkey_alloc],
[331,"pkey_free",0x14b,["int pkey"],RET.pkey_free],
[332,"statx",0x14c,[A.DFD,A.CONST_PATH,"unsigned flags","unsigned mask","struct statx *buffer"],RET.statx]

