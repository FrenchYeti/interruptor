# interruptor

*Work In Progess*

The home for Interruptor, a human-friendly interrupts hook library based on Frida's Stalker

Interruptor is the interrupts/systemcall hooking system from Dexcalibur.

If you like it, please consider to buy  :moneybag: [Dexcalibur Pro](https://www.reversense.com/dexcalibur) or :sparkling_heart: [sponsor me](https://github.com/sponsors/frenchyeti). Sponsor encourage me to free parts of Dexcalibur Pro and spend more free time on such projects :)

The purpose of this library is to provide to Frida users, a rich API able to produce **strace-like** trace + hook + configurable syscall args API.

It provides by default some useful features such as :
* File Descriptor lookup (to retrieve path)
* Bitmap parsing to have humean-friendly output
* Syscall hook using Frida's Interceptor style
* Better api to trace/change syscall args before/after
* Filterable modules and syscalls
* Coverage generation



## 1. Requirements

**Requirements :**

* frida
* frida-compile

**Install :**

Only from source for now (will move to NPM ASAP)
```
git clone https://github.com/FrenchYeti/interruptor
cd interruptor
npm install
npx tsc
frida-compile examples/simple_strace.js -o trace.js && frida -U -f <PACKAGE> -l trace.js
```

**Example**

#### Simple tracing
Simple tracing without hook from attach moment, with excluded module and syscall (by name)
```
var Interruptor = require('../dist/index.js').default.LinuxArm64();

Interruptor.newAgentTracer({
    exclude: {
        modules: ["linker64"],
        syscalls: ["clock_gettime"]
    }
}).start();

```

Output :
```
[/system/lib64/libc.so +0x3cc]   SVC :: 0x38   openat ( int dfd = 0xffffff9c , filename = /dev/ashmem , int flags = 0x80002 , umode_t mode = 0x0 ,  )    > (FD) 0x1f
[/system/lib64/libc.so +0x834]   SVC :: 0x50   fstat ( fd = 0x1f  /dev/ashmem   , struct __old_kernel_stat *statbuf = 0x7ffc01bdc8 ,  )    > 0x0
[/system/lib64/libc.so +0x3b4]   SVC :: 0x1d   ioctl ( fd = 0x1f  /dev/ashmem   , unsigned int cmd = 0x41007701 , unsigned long arg = 0x7ffc01be98 ,  )    > 0x0
[/system/lib64/libc.so +0x3b4]   SVC :: 0x1d   ioctl ( fd = 0x1f  /dev/ashmem   , unsigned int cmd = 0x40087703 , unsigned long arg = 0x2000 ,  )    > 0x0
[/system/lib64/libc.so +0xc24]   SVC :: 0xde   mmap ( addr = 0x0 , length = 0x2000 , prot = PROT_READ | PROT_WRITE   , int flags = 0x2 , fd = 0x1f  /dev/ashmem   , offset = 0x0 ,  )    > 0x76b45ab000
[/system/lib64/libc.so +0x174]   SVC :: 0x39   close ( fd = 0x1f  /dev/ashmem   ,  )    > 0x0
[/system/lib64/libc.so +0xc24]   SVC :: 0xde   mmap ( addr = 0x0 , length = 0x106000 , prot = PROT_READ | PROT_WRITE   , int flags = 0x4022 , fd = 0xffffffff  undefined   , offset = 0x0 ,  )    > 0x7611e6b000
[/system/lib64/libc.so +0xc54]   SVC :: 0xe2   mprotect ( unsigned long start = 0x7611e6b000 , size_t len = 0x1000 , unsigned long prot = 0x0 ,  )    > 0x0
[/system/lib64/libc.so +0xd14]   SVC :: 0xa7   prctl ( int option = 0x53564d41 , unsigned long arg2 = 0x0 , unsigned long arg3 = 0x7611e6b000 , unsigned long arg4 = 0x1000 , unsigned long arg5 = 0x76b72f3798 ,  )    > 0x0
[/system/lib64/libc.so +0xc24]   SVC :: 0xde   mmap ( addr = 0x0 , length = 0x5000 , prot = PROT_NONE   , int flags = 0x22 , fd = 0xffffffff  undefined   , offset = 0x0 ,  )    > 0x762f440000
[/system/lib64/libc.so +0xd14]   SVC :: 0xa7   prctl ( int option = 0x53564d41 , unsigned long arg2 = 0x0 , unsigned long arg3 = 0x762f440000 , unsigned long arg4 = 0x5000 , unsigned long arg5 = 0x76b72f35cc ,  )    > 0x0
[/system/lib64/libc.so +0xc54]   SVC :: 0xe2   mprotect ( unsigned long start = 0x762f441000 , size_t len = 0x3000 , unsigned long prot = 0x3 ,  )    > 0x0
[/system/lib64/libc.so +0xd14]   SVC :: 0xa7   prctl ( int option = 0x53564d41 , unsigned long arg2 = 0x0 , unsigned long arg3 = 0x762f441000 , unsigned long arg4 = 0x3000 , unsigned long arg5 = 0x76b72f360e ,  )    > 0x0
[/system/lib64/libc.so +0x1f28]   SVC :: 0xdc   clone ( unsigned long = 0x3d0f00 , unsigned long = 0x7611f704e0 , int * = 0x7611f70500 , int * = 0x7611f70588 , unsigned long = 0x7611f70500 ,  )    > 0x6ae
```

More complete example are provided into examples directory.

#### Simple tracing with hooked "read" syscall and dynamic loading

```
Interruptor.newAgentTracer({
    exclude: {
        syscalls: ["clock_gettime"]
    },
    svc: {
         read: {
             onLeave: function(ctx){
                 let res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils().toScanPattern('frida'));
                 if(res.length > 0){
                     res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41]));
                     console.log("remove 'frida' pattern from resulting buffer");
                 }
             }
         }
    }
}).startOnLoad(/<YOUR_LIB>/g); 

```


#### Simple tracing with coverage

```
Interruptor.newAgentTracer({
    exclude: {
        syscalls: ["clock_gettime"]
    },
    coverage: {
        enabled: true,
        fname: "/data/data/<YOUR_APP>/test.drcov",
        stops: {
            count: 2000 // stop after 2000 basic blocks captured
        }
    }
}).startOnLoad(/<YOUR_LIB>/g);
```

## 2. Supports

**Architectures**
* ARM64 : SVC (syscall), HVC (hypervisor)

**APIs**
* Linux kernel API (syscall)

## 3. Roadmap

| Task  | Description  | Status  |
|---|---|---|
| Syscall trace | Improve syscall printed output  |   |
| ARM 32bit| Add Aarch32 support |   |
| ARM HVC| Improve ARM HyperVisor Call support (HVC)  |   |
| ARM SMC| Add ARM Secure Monitor Call support (SMC)  |   |
| Syscall arg parsing | Improve argument parsing and add API for each args with known type (including structures)  |   |
| Signal trace | Add trace of signals  |   |
| Strace options | Implement same options than *strace* tool   |   |
| Follow Thread  | Add follow thread support to track multi threaded exec  |   |
| Follow Fork  | Follow automatically child processes  |   |
| Multi-process (isolated, ...)  | Follow several process in same time.  |   |
| Incremental drcov | Instead of writing all coverage data one time into output file, update it at runtime to handle case where process crashes |   |

## 4. Documentation

[TODO]

There are mainly two way to hook interrupts depending of yours needs.

**Agent Tracer**

When you want to use only a Frida agent script (and not host script).

*Limitation:*

Cannot follow children/multiples processes.

**Standalone Tracer [TODO]**

When you need to follow children processes, or external processes.
It works even if there is not link between traces processes.

In this case, the final script runs on the host and act like strace tool into the host or the device.





