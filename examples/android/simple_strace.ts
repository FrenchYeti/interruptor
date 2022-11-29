import target from './index.linux.arm64.js';

const Interruptor = target.LinuxArm64({});

Interruptor.newAgentTracer({
    followThread: true,
    scope: {
        syscalls: {
            exclude:  [/clock_gettime/]
        },
        modules: {
            exclude: [/linker/]
        }
    },
    onStart: function(){
        console.log("Entering into lib")
    }
}).startOnLoad(/libNAME.so/,{ threshold:1 });






