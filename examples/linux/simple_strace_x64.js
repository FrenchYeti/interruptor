var Interruptor = require('../dist/android-x64-strace.min.js').target.LinuxX64();


Interruptor.newAgentTracer({
    followThread: true,
    exclude : {
        syscall: [/clock_gettime/]
    }
}).start();



