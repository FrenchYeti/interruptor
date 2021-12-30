# interruptor

The [future] home for Interruptor, a human-friendly interrupts hook library based on Frida's Stalker

Interruptor is the interrupts/systemcall hooking system from Dexcalibur.

## Requirements

* frida
* frida-compile

## Documentation

There are mainly two way to hook interrupts depending of yours needs.

### A. Agent Tracer

When you xant to use only a Frida agent script (and not host script).

### B. Remote Trace

When you need to follow children processes, or external processes.
