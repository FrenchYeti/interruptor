var Interruptor = require('../dist/index.js').default.LinuxArm64();


Interruptor.newAgentTracer({
    exclude: {
        syscalls: ["clock_gettime"]
    }
}).start();



