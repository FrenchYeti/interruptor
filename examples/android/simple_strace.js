var Interruptor = require('./android-arm64-strace.min.js').target.LinuxArm64();

// Java.deoptimizeEverything();

Java.perform(()=>{
    Interruptor.newAgentTracer({
        exclude: {
            syscalls: ["clock_gettime"]
        }
    }).start();
});




