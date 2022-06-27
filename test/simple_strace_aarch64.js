var Interruptor = require('../dist/android-aarch64-strace.min.js').target.LinuxArm64();


Interruptor.newAgentTracer({
    followThread: true,
    exclude : {
        syscall: [/clock_gettime/]
    }
}).start();



