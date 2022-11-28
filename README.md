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

Full documentation of tha API is available here : [Interruptor Doc](https://frenchyeti.github.io/interruptor-codedoc/index.html)

## 1. How to use

In fact, install is not necessary. Just include the released minified JS file corresponding to your target os/arch into your Frida agent's script. Or call it throuh Frida's Codeshare.


### 1.A Using Frida's Codeshare (without configuration)

Warning : this methods don't allow you to configure Interruptor. So, tracing of obfuscated or multi-threaded application could failed.

This method is only  provided for training purpose.
```
frida --codeshare FrenchYeti/android-arm64-strace -f YOUR_BINARY
```


### 1.A From latest release (for version <= 0.2)

**Requirements :**

* frida

Donwload [latest release](https://github.com/FrenchYeti/interruptor/releases) for your architecture into your working directory, 
and do:

```
import target from './index.linux.arm64.js';
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

### 1.C From source

**Requirements :**

* frida

Only from source for now (will move to NPM ASAP)
```
git clone https://github.com/FrenchYeti/interruptor
cd interruptor
npm install
```

And finally :
```
frida -U -l ./examples/simple_strace.ts -f <PACKAGE> 
```

## 2. Examples

### 2.A Simple tracing (<=0.2)
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

### 2.B Simple tracing with hooked "read" syscall and dynamic loading

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


### 2.C Simple tracing with coverage

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





