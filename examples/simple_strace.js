var Interruptor = require('../dist/index.js').default.LinuxArm64();

Java.deoptimizeEverything();

Java.perform( ()=> {
    Interruptor.newAgentTracer({
        tid: Process.getCurrentThreadId(),
        exclude: {
            modules: ["linker64"],
            syscalls: ["clock_gettime"]
        }/*,
        svc: {
             read: {
                 onLeave: function(ctx){
                     let res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils().toScanPatt('frida'));
                     if(res.length > 0){

                         res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41]));
                         console.log("Sanitizing 'read' syscall : remove 'frida' pattern in memory");
                     }
                 }
             },
             openat: {
                 onLeave: function(ctx){
                     if(ctx.dxcFD==null) ctx.dxcFD = {};
                     ctx.dxcFD[ctx.x0.toInt32()+""] = ctx.dxcOpts;
                 }
             }
        }*/
    }).start();
})


