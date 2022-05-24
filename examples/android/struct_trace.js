var Interruptor = require('./android-arm64-strace.min.js').target.LinuxArm64();
var KTypes = require('../frida-systruct/src/android-arm64.js');

Interruptor.newAgentTracer({
    exclude: {
        syscalls: ["clock_gettime"]
    },
    types: Interruptor.newTypeDefinition(KTypes)
}).start();



