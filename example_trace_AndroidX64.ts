

import target from './index.linux.x64.js';

const Interruptor = target.LinuxX64({});

let deployed = false;

Interruptor.newAgentTracer({
    followThread: true,
    emulator: false,
    scope: {
        syscalls: {
            exclude:  []
        },
        modules: {
            exclude: []
        }
    },
    onStart: ()=>{
        if(!deployed){
            deployed = true;
            Interceptor.attach(
                Process.findModuleByName('libc.so').getExportByName("exit"),
                {
                    onEnter: function(args){
                        console.warn("[LIBC] exit")
                    }
                }
            );
        }
    }
}).startOnLoad(/\.so$/g, {threshold:1});






