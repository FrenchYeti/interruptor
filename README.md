# interruptor

*Work In Progess*

The home for Interruptor, a human-friendly interrupts hook library based on Frida's Stalker

Interruptor is the interrupts/systemcall hooking system from Dexcalibur.

The purpose of this library is to provide to Frida users, a rich API able to produce **strace-like** trace + hook + configurable syscall args API.



## 1. Requirements

* frida
* frida-compile

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

There are mainly two way to hook interrupts depending of yours needs.

**Agent Tracer**

When you want to use only a Frida agent script (and not host script).

*Limitation:*

Cannot follow children/multiples processes.

**Standalone Tracer [TODO]**

When you need to follow children processes, or external processes.
It works even if there is not link between traces processes.

In this case, the final script runs on the host and act like strace tool into the host or the device.





