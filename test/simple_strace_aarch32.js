var Interruptor = require('../dist/android-aarch32-strace.min.js').target.LinuxAarch32();


Interruptor.newAgentTracer({
    followThread: false,
    exclude : {
        syscalls: [/clock_gettime/]
    }
}).start();



