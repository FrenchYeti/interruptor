var Interruptor = require('../dist/android-arm64-strace.min.js').target.LinuxArm64();

Interruptor.newAgentTracer({
    followThread: true
}).startOnLoad(/\.so/,{
    threshold: 1
});





