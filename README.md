# Interruptor

![ci](https://github.com/FrenchYeti/interruptor/workflows/CI/badge.svg)

*Work In Progess*

The home for Interruptor, a human-friendly interrupts hook library based on Frida's Stalker

Interruptor is the interrupts/systemcall hooking system from Dexcalibur.

Quick start for Android app (could not work as is with obfuscated app) :
```
frida --codeshare FrenchYeti/android-arm64-strace -U -f YOUR_BINARY
```

If you like it, please consider to buy  :moneybag: [Dexcalibur Pro](https://www.reversense.com/dexcalibur) or :sparkling_heart: [sponsor me](https://github.com/sponsors/frenchyeti). Sponsor encourage me to free parts of Dexcalibur Pro and spend more free time on such projects :)

The purpose of this library is to provide to Frida users, a rich API able to produce **strace-like** trace + hook + configurable syscall args API.

It provides by default some useful features such as :
* File Descriptor lookup (to retrieve path)
* Bitmap parsing to have humean-friendly output
* Syscall hook using Frida's Interceptor style
* Better api to trace/change syscall args before/after
* Filterable modules and syscalls
* Coverage generation

### Full documentation of the API is [now available](https://frenchyeti.github.io/interruptor-codedoc/index.html)

## 1. How to use it

Interruptor can be used by following different approach. I Hope you will be able to find the best one for you :

- A. Interruptor as NPM package in your hooking project
- B. Importing minified file per architecture/os 
- C. Using Frida's CodeShare (not yet configurable, less suitable for tampering)
- C. From source

### Case A : Using Interruptor package

**It is the BEST and more reliable way to use Interruptor** 

This method require Frida >= 16.x is you write your hook in Typescript.

Basically, create a new folder for your hooks or move into your workspace :
```
mkdir my_workspace && cd my_workspace
```

And install the package :
````
npm install @reversense/interruptor
````

After successful install, you can create a basic script (`script.ts`) like it (TypeScript) :
```
import target from '@reversense/interruptor/index.linux.arm64.js';

const Interruptor = target.LinuxArm64({});

Interruptor.newAgentTracer({
    followThread: true,
    scope: {
        syscalls: {
            exclude:  [/clock_gettime/]
        },
        modules: {
            exclude: [/linker/]
        }
    },
    onStart: function(){
        console.log("Entering into lib")
    }
}).start();
```

Then, just launch your frida script like this :
```
frida -U -l ./script.ts -f <YOUR_APP>
```

May be you noted TS script is passed directly to `frida` instead of `frida-compile`, such thing is possible with Frida >= 16.x .

### Case B : From minified files

**Requirements :**

* frida

Download [latest release](https://github.com/FrenchYeti/interruptor/releases) for your architecture into your working directory, 
and do:

```
import target from './index.linux.arm64.min.js';
import {DebugUtils} from "./src/common/DebugUtils.js";

const Interruptor = target.LinuxArm64({});

Interruptor.newAgentTracer({
    followThread: true,
    scope: {
        syscalls: {
            exclude:  [/clock_gettime/]
        },
        modules: {
            exclude: [/linker/]
        }
    }
}).start();
```

Time to deploy hooks can be configured to be when a particular library is loaded. See options below.


### Case C : Using Frida's Codeshare (not yet configurable)

**Warning : this methods don't allow you to configure Interruptor. So, tracing of obfuscated or multi-threaded application could fail.**

This method is only provided for linux/arm64 and training purpose.
```
frida --codeshare FrenchYeti/android-arm64-strace -f YOUR_BINARY
```

### Case D : From source

**Requirements :**

* frida

Don't be afraid by dependencies : Interruptor has only common dev dependencies to provide types and unit test features. 

Download or clone the repository, and install it
```
git clone https://github.com/FrenchYeti/interruptor
cd interruptor
npm install
npm run build
```

When it is done, just copy one of examples into repository root folder :
```
cp ./examples/android/simple_trace.ts .
```


And finally :
```
frida -U -l ./simple_strace.arm64.ts -f <PACKAGE> 
```



## 2. Examples

### 2.A Simple tracing 

#### With recent version (> 0.2)
Simple tracing without hook from attach moment, with excluded module and syscall (by name)
```
import target from '@reversense/interruptor/index.linux.arm64.js';

const Interruptor = target.LinuxArm64({});

// better results, when app is loaded
Java.perform(()=>{
    Interruptor.newAgentTracer({
        scope: {
            syscalls: { exclude:  ["clock_gettime"] },
            modules: { exclude: [/linker64/] }
        }
    }).start();
});
```

#### With version <= 0.2
Simple tracing without hook from attach moment, with excluded module and syscall (by name)
```
var Interruptor = require('./android-arm64-strace.min.js').target.LinuxArm64();

// better results, when app is loaded
Java.perform(()=>{
    Interruptor.newAgentTracer({
        exclude: {
            modules: ["linker64"],
            syscalls: ["clock_gettime"]
        }
    }).start();
});
```

#### Output :

Output :
```
	------- [TID=4407][libutils.so][0x76d9fd6388] Thread routine start -------
	[INTERRUPTOR][STARTING] Tracing thread 4407 []
	[STARTING TRACE] UID=1 Thread 4407
 [TID=4407] [/system/lib64/libc.so +0x630]   setpriority (   which = NULL ,  who = 0x0 ,  ioprio = 0x0  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x928]   openat (   dfd = AT_FDCWD  ,  filename = /proc/4407/timerslack_ns ,  flags = O_RDONLY | O_WRONLY | O_CLOEXEC ,  mode =   )    > (FD) 0x1f
 [TID=4407] [/system/lib64/libc.so +0x990]   write (   fd = 31  /proc/4407/timerslack_ns   ,  buf = 50000 ,  size = 0x5  )    > 0x5
 [TID=4407] [/system/lib64/libc.so +0x6d0]   close (   fd = 31  /proc/4407/timerslack_ns    )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x270]   prctl (   opt = PR_SET_NAME ,  arg2 = 0x7651d1d560 ,  arg3 = 0x0 ,  arg4 = 0x0 ,  arg5 = 0x0  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x1b0]   mprotect (   addr = 0x7641dae000 ,  size = 0x1000 ,  prot = PROT_NONE  )    > 0 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0xf0]   madvise (   addr = 0x7641dae000 ,  size = 0xfb000 ,  behavior = MADV_DONTNEED  )    > 0 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0x928]   openat (   dfd = AT_FDCWD  ,  filename = /dev/ashmem ,  flags = O_RDONLY | O_RDWR | O_CLOEXEC ,  mode =   )    > (FD) 0x1f
 [TID=4407] [/system/lib64/libc.so +0xd90]   fstat (   fd = 31  /dev/ashmem   ,  *statbuf = 0x7641ea9e68  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x910]   ioctl (   fd = 31  /dev/ashmem   ,  cmd = 0x41007701 ,  arg = 0x7641ea9f38  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x910]   ioctl (   fd = 31  /dev/ashmem   ,  cmd = 0x40087703 ,  arg = 0x2000  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x180]   mmap (   start_addr = 0x0 ,  size = 0x2000 ,  prot = PROT_READ | PROT_WRITE ,  flags = MAP_PRIVATE ,  fd = undefined ,  offset = 0x0  )    > 0x76599ee000 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0x6d0]   close (   fd = 31  /dev/ashmem    )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x1b0]   mprotect (   addr = 0x12f80000 ,  size = 0x40000 ,  prot = PROT_READ | PROT_WRITE  )    > 0 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0x8e0]   getpriority (   which = NULL ,  who = 0x0  )    > 0x14
 [TID=4407] [/system/lib64/libc.so +0x270]   prctl (   opt = PR_SET_NAME ,  arg2 = 0x7641eaa148 ,  arg3 = 0x343a7265646e6942 ,  arg4 = 0x315f363833 ,  arg5 = 0x28  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0xf70]   getuid (  )    > 10089
 [TID=4407] [/system/lib64/libc.so +0x910]   ioctl (   fd = 12  undefined   ,  cmd = 0xc0306201 ,  arg = 0x7641eaa2b8  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x180]   mmap (   start_addr = 0x0 ,  size = 0xfe000 ,  prot = PROT_READ | PROT_WRITE ,  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE ,  fd = undefined ,  offset = 0x0  )    > 0x7641263000 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0x1b0]   mprotect (   addr = 0x7641263000 ,  size = 0x1000 ,  prot = PROT_NONE  )    > 0 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0x270]   prctl (   opt = PR_SET_VMA ,  arg2 = 0x0 ,  arg3 = 0x7641263000 ,  arg4 = 0x1000 ,  arg5 = 0x76de1b64c5  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x180]   mmap (   start_addr = 0x0 ,  size = 0x5000 ,  prot = PROT_NONE ,  flags = MAP_PRIVATE | MAP_ANONYMOUS ,  fd = undefined ,  offset = 0x0  )    > 0x76599e9000 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0x270]   prctl (   opt = PR_SET_VMA ,  arg2 = 0x0 ,  arg3 = 0x76599e9000 ,  arg4 = 0x5000 ,  arg5 = 0x76de1b62f9  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x1b0]   mprotect (   addr = 0x76599ea000 ,  size = 0x3000 ,  prot = PROT_READ | PROT_WRITE  )    > 0 SUCCESS
 [TID=4407] [/system/lib64/libc.so +0x270]   prctl (   opt = PR_SET_VMA ,  arg2 = 0x0 ,  arg3 = 0x76599ea000 ,  arg4 = 0x3000 ,  arg5 = 0x76de1b633b  )    > 0x0
 [TID=4407] [/system/lib64/libc.so +0x1ca8]   clone (   unsigned long = 0x3d0f00 ,  unsigned long = 0x76413604e0 ,  int * = 0x7641360500 ,  int * = 0x7641360588 ,  unsigned long = 0x7641360500  )    > 0x1139
 [TID=4407] [/system/lib64/libc.so +0x2c]   futex (   word = 0x7641360570 ,  op = FUTEX_WAKE_PRIVATE ,  u32 val = 0x1 ,  *utime = 0x0 ,  u32 *uaddr2 = 0x0 ,  u32 val3[ = 0x0  )    > 0x1
 [TID=4407] [/system/lib64/libc.so +0x2c]   futex (   word = 0x7659b1c248 ,  op = FUTEX_WAKE_PRIVATE ,  u32 val = 0x7fffffff ,  *utime = 0x0 ,  u32 *uaddr2 = 0x0 ,  u32 val3[ = 0x0  )    > 0x0

	------- [TID=4409][libutils.so][0x76d9fd6388] Thread routine start -------
	[INTERRUPTOR][STARTING] Tracing thread 4409 []
	[STARTING TRACE] UID=2 Thread 4409
 [TID=4409] [/system/lib64/libc.so +0x630]   setpriority (   which = NULL ,  who = 0x0 ,  ioprio = 0x0  )    > 0x0
 [TID=4409] [/system/lib64/libc.so +0x928]   openat (   dfd = AT_FDCWD  ,  filename = /proc/4409/timerslack_ns ,  flags = O_RDONLY | O_WRONLY | O_CLOEXEC ,  mode =   )    > (FD) 0x1f
 [TID=4409] [/system/lib64/libc.so +0x990]   write (   fd = 31  /proc/4409/timerslack_ns   ,  buf = 50000 ,  size = 0x5  )    > 0x5
 [TID=4409] [/system/lib64/libc.so +0x6d0]   close (   fd = 31  /proc/4409/timerslack_ns    )    > 0x0
 [TID=4409] [/system/lib64/libc.so +0x270]   prctl (   opt = PR_SET_NAME ,  arg2 = 0x765364f010 ,  arg3 = 0x0 ,  arg4 = 0x0 ,  arg5 = 0x0  )    > 0x0
 [TID=4409] [/system/lib64/libc.so +0x1b0]   mprotect (   addr = 0x7641264000 ,  size = 0x1000 ,  prot = PROT_NONE  )    > 0 SUCCESS
 [TID=4409] [/system/lib64/libc.so +0xf0]   madvise (   addr = 0x7641264000 ,  size = 0xfb000 ,  behavior = MADV_DONTNEED  )    > 0 SUCCESS
 [TID=4409] [/system/lib64/libc.so +0x928]   openat (   dfd = AT_FDCWD  ,  filename = /dev/ashmem ,  flags = O_RDONLY | O_RDWR | O_CLOEXEC ,  mode =   )    > (FD) 0x1f
 [TID=4409] [/system/lib64/libc.so +0xd90]   fstat (   fd = 31  /dev/ashmem   ,  *statbuf = 0x764135fe68  )    > 0x0
 [TID=4409] [/system/lib64/libc.so +0x910]   ioctl (   fd = 31  /dev/ashmem   ,  cmd = 0x41007701 ,  arg = 0x764135ff38  )    > 0x0
 [TID=4409] [/system/lib64/libc.so +0x910]   ioctl (   fd = 31  /dev/ashmem   ,  cmd = 0x40087703 ,  arg = 0x2000  )    > 0x0
 [TID=4409] [/system/lib64/libc.so +0x180]   mmap (   start_addr = 0x0 ,  size = 0x2000 ,  prot = PROT_READ | PROT_WRITE ,  flags = MAP_PRIVATE ,  fd = undefined ,  offset = 0x0  )    > 0x7656380000 SUCCESS
 [TID=4409] [/system/lib64/libc.so +0x6d0]   close (   fd = 31  /dev/ashmem    )    > 0x0
 [TID=4409] [/system/lib64/libc.so +0x1b0]   mprotect (   addr = 0x12fc0000 ,  size = 0x40000 ,  prot = PROT_READ | PROT_WRITE  )    > 0 SUCCESS
```

More complete example are provided into examples directory.

### 2.B Simple tracing with hooked "read" syscall and dynamic loading

```
Interruptor.newAgentTracer({
    scope: {
        syscalls: { exclude:  ["clock_gettime"] }
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


### 2.C Simple tracing with coverage

```
Interruptor.newAgentTracer({
    scope: {
        syscalls: { exclude:  ["clock_gettime"] }
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

## 3. Supports

**Architectures**
* Aarch64 : SVC (syscall), HVC (WiP, hypervisor)
* x64 : SYSCALL

**APIs**
* Linux kernel API (syscall)

## 4. Roadmap


**How to help ?**

The following links enumerates Linux syscall for several architectures, feel free to extend Interruptor and do a PR :) 

https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html


## 5. Documentation

### 5.A Create a new agent

First, you need to get the tracer factory adapted to your OS/Architecture :
For now only "LinuxArm64()" is available.
```
var Interruptor = require('../dist/index.js').target.LinuxArm64();
```

Next step is to intanciante a tracer with a specific options. 
Options are not mandatory but can change a lot the behavior and output.
```
Interruptor.newAgentTracer( /* opts */);
```

A full list of options can be found into the next section.

Final step, choose when you want to start to trace :
* A. When frida script is executed
```
var Interruptor = require('../dist/index.js').target.LinuxArm64();

Interruptor.newAgentTracer( /* opts */).start();
```

* B. The first time a module is opened by the linker
```
var Interruptor = require('../dist/index.js').target.LinuxArm64();

Interruptor.newAgentTracer( /* opts */).startOnLoad(/my_lib\.so$/g);
```

* C. From your hooks
```
var Interruptor = require('../dist/index.js').target.LinuxArm64();

Interceptor.attach( /* ... */,{
    onEnter: function(){
        Interruptor.newAgentTracer( /* opts */).start();
    }
})
```

### 5.B Options

All options are optional, except some explicited options
Below, a complete overview of options  :
```
{
    followFork: TRUE | FALSE ] // TODO
    followThread: TRUE | FALSE ] // TODO
    tid: <Thread ID>,
    pid: <PID>,
    onStart: <callback function>,
    exclude: {
        syscalls: [ ... syscall names ... ], // "read", ...
        modules: [ ... module names ... ], // "linker64" ...
        svc: [ ... SVC number ...], // 0x1e, ...
        hvc: [ ... HVC number ...]
    },
    // coverage options
    coverage: {
        enabled = true,
        flavor = "dr", // not supported
        fname = "/data/data/my_app/drcov.dat", // MANDATORY
        stops = 2000 // MANDATORY
    },
    // output options (partially implemented)
    output: {
        flavor: "dxc", // "strace" is coming
        tid: true,
        pid: false,
        module: true,
        dump_buff: true, // dump buffer when ptr+size are known 
        highlight: {
            syscalls: []
        }
    },
    // hooks
    svc: {
        [syscall_text_name]: {
            onEnter: function(pContext){
            
            },
            onLeave: function(pContext){
            
            }
        }
    }
}
```
#### 5.B.1 Filtering

**! Important !** 

When a system is excluded, it is not hooked and printed. By consequence, some feature can not work properly such as file descriptor lookup when "openat" is excluded.


All interruption types can be filtered using at least the interruption number. Additionnally, Modules and System calls can be filtered by name (string pattern or regexp)  or by properties (using a filtering function).

```
Interruptor.newAgentTracer({
    followThread: false,
    include: {
        modules: ["libc.so"],
        syscalls: [/^get/,"read","openat","close",/^m/]
    },
    exclude: {
        syscalls: [ /time$/]
    },
    output: {
        tid: true,
        inst: true,
        module: true
    }
}).start();
```


Modules and System calls are filtering by following one of these tree ways : Hook/trace only instructions
* from a list of  mapped modules
* from modules not included into "exclude list" of mapped modules
* from included modules - excluded modules

```
include: {
    syscalls: [
        "read",
        "openat",
        "close",
        /^m/,       // mprotect, madvise, mmap, ...
        /^get/     // getpriority, getuid, getpid,  ...
    ]
},
```

### 5.C Tracer types

There are mainly two way to hook interrupts depending of yours needs.

**Agent Tracer**

When you want to use only a Frida agent script (and not host script).

*Limitation:*

Cannot follow children/multiples processes.

**Standalone Tracer [TODO]**

When you need to follow children processes, or external processes.
It works even if there is not link between traces processes.

In this case, the final script runs on the host and act like strace tool into the host or the device.





