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




/*
res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils.toScanPatt('su_exec'));
if(res.length > 0){

    res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41,0x41,0x41]));
    console.log("Sanitizing 'read' syscall : remove 'su_exec' pattern in memory");
}


res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils.toScanPatt('/data/local'));
if(res.length > 0){

    res.map( m => m.address.writeByteArray([0x2f,0x73,0x79, 0x73,0x74, 0x65, 0x6d, 0x2f,0x6c, 0x69,0x62, 0x36,0x34, 0x2f]));
    console.log("FRIDA DETECTED (2) == TAMPERING ... ");
    console.log(hexdump(ctx.x1,{ ascii:true, length:ctx.x2.toInt32() }));
}


let res3 = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils.toScanPatt('magisk'));
if(res3.length > 0){

    res3.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41,0x41]));
    console.log("Sanitizing 'read' syscall : remove 'magisk' pattern in memory");
}*/
