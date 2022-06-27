var Interruptor = require('./android-arm64-strace.min.js').target.LinuxArm64();

Interruptor.newAgentTracer({
    exclude: {
        syscalls: ["clock_gettime"]
    },
    svc: {
         read: {
             onLeave: function(ctx){
                 let res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils().toScanPattern('frida'));
                 if(res.length > 0){
                     res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41]));
                     console.log("remove 'frida' pattern from resulting buffer");
                 }
             }
         }
    }
}).startOnLoad(/<YOUR_LIB>/g);

