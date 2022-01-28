var Interruptor = require('./android-arm64-strace.min.js').target.LinuxArm64();

Interruptor
    .newAgentTracer({
        exclude: {
            syscalls: ["clock_gettime"]
        }
    })
    .startOnLoad(/<MY_LIB>/g);


