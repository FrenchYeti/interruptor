var Interruptor = require('../dist/index.js').default.LinuxArm64();


Interruptor.newAgentTracer({
    exclude: {
        syscalls: ["clock_gettime"]
    },
    coverage: {
        enabled: true,
        fname: "/data/data/<YOUR_APP>/test.drcov",
        stops: {
            count: 2000 // stop after 2000 basic blocks captured
        }
    }
}).startOnLoad(/<YOUR_LIB>>/g);


