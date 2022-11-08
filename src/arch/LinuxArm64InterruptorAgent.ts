import {InterruptorAgent, InterruptSignatureMap} from "../common/InterruptorAgent.js";
import {InterruptorGenericException} from "../common/InterruptorException.js";
import {T, L, F} from "../common/Types.js";
import * as DEF from "../kernelapi/LinuxArm64Flags.js";
import {TypedData} from "../common/TypedData.js";
import {SVC} from "../syscalls/LinuxAarch64Syscalls.js";
import {IStringIndex} from "../utilities/IStringIndex.js";
import {SyscallHandlersMap, SyscallMap} from "../syscalls/ISyscall.js";
import {DebugUtils} from "../common/DebugUtils.js";

interface RichContextOptions extends Arm64CpuContext {
    _extra?:any;
    [name:string] :any;
}

interface ExtraContext {
    orig?:NativePointer;
    FD?:any;
    WD?:any;
    SOCKFD?:any;
    DFD?:any;
    [name:string] :any;
}

interface RichArm64CpuContext extends Arm64CpuContext {
    dxc?:ExtraContext;
    log?:string;
    dxcOpts?:RichContextOptions;
    dxcRet?:any;
}




// GPR = Global Purpose Register prefix => x/r
const GPR = "x";
const SVC_NUM = 0;
const SVC_NAME = 1;
const SVC_ARG = 3;
const SVC_RET = 4;
const SVC_ERR = 5;

//{AT_, E, MAP_, X}
const AT_ = DEF.AT_;
const E = DEF.E;
const MAP_ = DEF.MAP_;
const X = DEF.X;

const SVC_MAP_NUM:SyscallHandlersMap = {};
const SVC_MAP_NAME:SyscallMap = {};

SVC.map(x => {
    SVC_MAP_NAME[x[1] as string] = x;
    SVC_MAP_NUM[x[0]] = x;
});


export const KAPI = {
    CONST: DEF,
    SVC: SVC_MAP_NAME,
    SVC_ARG: SVC_ARG,
    ERR: DEF.ERR
};

export class LinuxArm64InterruptorAgent extends InterruptorAgent implements IStringIndex {

    loadCtr = 0;

    filter_name: string[] = [];
    filter_num: string[] = [];

    svc_hk: any = {};
    hvc_hk: any = {};
    smc_hk: any = {};
    irq_hk: any = {};

    constructor(pConfig:any, pDoFollowThread:any, pInterrupts:InterruptSignatureMap) {
        super(pConfig, pDoFollowThread, pInterrupts);
        this.configure(pConfig);
    }

    /*_setupDelegateFilters( pTypes:string, pOpts:any):void {
        if(pOpts == null) return;

        const o = pOpts;
        const f = (this as any)[pTypes];

        ["svc","hvc","smc"].map( x => {
            if(o.hasOwnProperty(x))
                f[x] = o[x];
        });

        if(f.hasOwnProperty("syscalls") && f.syscalls != null){
            f.svc = this.getSyscallList(f.syscalls);
        }
    }*/

    configure(pConfig:any){
        if(pConfig == null) return;

        for(const k in pConfig){
            switch (k){
                case 'svc':
                    for(const s in pConfig.svc) this.onSupervisorCall(s, pConfig.svc[s]);
                    break;
                case 'hvc':
                    for(const s in pConfig.hvc) this.onHypervisorCall( parseInt(s as any, 16), pConfig.hvc[s]);
                    break;
                case 'filter_name':
                    this.filter_name = pConfig.filter_name;
                    break;
                case 'filter_num':
                    this.filter_num = pConfig.filter_num;
                    break;
            }
        }

        this.setupBuiltinHook();
    }


    onSupervisorCall(pIntName:string, pHooks:any){
        const sc = SVC_MAP_NAME[pIntName];
        if(sc == null) throw InterruptorGenericException.UNKNOW_SYSCALL(pIntName);
        if(pHooks.hasOwnProperty('onEnter') || pHooks.hasOwnProperty('onLeave')){
            this.svc_hk[sc[0]] = pHooks
        }

    }

    onHypervisorCall(pIntNum:number, pHooks:any){
        if(pHooks.hasOwnProperty('onEnter') || pHooks.hasOwnProperty('onLeave')){
            this.hvc_hk[pIntNum] = pHooks
        }

    }

    setupBuiltinHook(){
        // nothing here
    }

    locatePC( pContext: any):string{
        let l = "", tid =-1;
        const r = Process.findRangeByAddress(pContext.pc);

        if(this.output.tid) {
            tid = Process.getCurrentThreadId();
            l += `\x1b[1;${this.output._tcolor}m [TID=${tid}] \x1b[0m`;

        }

        if(this.output.module){
            if(r != null){
                if(r.file != null){
                    if(this.output.hidePackage!=null){
                        l +=  `[${ r.file.path.replace(this.output.hidePackage, "HIDDEN")} +${pContext.pc.sub(r.base)}]`;
                    }else{
                        l +=  `[${ r.file.path } +${pContext.pc.sub(r.base)}]`;
                    }
                }else{
                    l +=  `[${r.base} +${pContext.pc.sub(r.base)}]`;
                }
            }else{
                l += `[<unknow>  lr=${pContext.lr}]`;
            }
        }

        if(this.output.lr)
            l += `[lr=${pContext.lr}]`;

        return l;
    }

    startOnLoad( pModuleRegExp:RegExp, pOptions:any = null):any {
        let  do_dlopen = null, call_ctor = null, scopedTrace = null, match:string|null=null;
        // eslint-disable-next-line @typescript-eslint/no-this-alias
        const self=this;
        const extra:any = null;

        //let opts = pOptions;
        const linkerMod = Process.findModuleByName('linker64');

        if(linkerMod==null){
            throw new Error("[ERROR] Linker64 cannot be hooked. Replace startOnLoad() by start(). Exit.")
        }
        linkerMod.enumerateSymbols().forEach(sym => {
            if (sym.name.indexOf('do_dlopen') >= 0) {
                do_dlopen = sym.address;
            } else if (sym.name.indexOf('call_constructor') >= 0) {
                call_ctor = sym.address;
            } else if(sym.name.indexOf('__dl__ZN11ScopedTrace3EndEv') >= 0){
                scopedTrace = sym.address;
            }
        });

        if(this.emulator && scopedTrace!=null){
            const ScopedTraceEnd = new NativeCallback(():number=>{
                return 1;
            }, 'int', ['int']);

            Interceptor.replace(scopedTrace, ScopedTraceEnd);
        }

        if(extra != null){
            Interceptor.attach(extra,  {
                onEnter: function(args){
                    this.out = args[0];
                    console.log( hexdump(this.out,{length:64}) );
                },
                onLeave: function(){
                    //console.log( hexdump(this.out,{length:64}) );
                }
            });
        }


        if(do_dlopen==null){
            throw new Error("[ERROR] Linker64 cannot be hooked : do_dlopen not found. Please fill an issue.");
        }

        Interceptor.attach(do_dlopen, function (args) {
            const p = args[0].readUtf8String();

            if(p!=null && pModuleRegExp.exec(p) != null){
                match = p;
            }
        });

        if(call_ctor==null){
            throw new Error("[ERROR] Linker64 cannot be hooked : call_ctor not found. Please fill an issue.");
        }

        Interceptor.attach(call_ctor, {
            onEnter:function () {
                if(match==null) return;
                const tmp = match;

                console.warn("[LINKER] Loading '"+match+"'");
                if(pOptions!=null && pOptions.hasOwnProperty('condition')){
                    if(!pOptions.condition(match, this)){
                        match = null;
                        return ;
                    }
                }

                console.warn("[INTERRUPTOR][STARTING] Module '"+match+"' is loading, tracer will start");
                match = null;

                self.start();

                if(pOptions!=null && pOptions.hasOwnProperty('threshold')){
                    //console.log(self.loadCtr, pOptions.threshold)
                    if(self.loadCtr < pOptions.threshold){
                        self.loadCtr++;
                        self.onStart( tmp, this);
                    }else{
                        console.warn("[INTERRUPTOR][STARTING] Threshold reached");
                        match = null;
                        return ;
                    }
                }else{
                    self.onStart( tmp, this);
                }

            }
        });
    }



    /**
     * To parse memory according to the structure defined by *pFormat*
     *
     * @param pContext
     * @param pFormats
     * @param pPointer
     * @param pSeparator
     * @param pAlign
     */
    parseStruct( pContext:any, pFormats:TypedData[], pPointer:NativePointer, pSeparator ="\n", pAlign = false):string {

        let msg:string = " {"+pSeparator;
        let fmt:TypedData, v = "", val:any = null;
        let offset =0;

        //console.log("DSTRUCT",JSON.stringify(pFormats));

        for(let i=0; i<pFormats.length; i++){
            fmt = pFormats[i];
            if(fmt==null) continue;
            //console.log("TYPED_DATA",JSON.stringify(fmt));
            switch(fmt.t){
                case T.SHORT:
                    val = pPointer.add(offset).readShort();
                    offset += 2;
                    break;
                case T.USHORT:
                    val = pPointer.add(offset).readUShort();
                    offset += 2;
                    break;
                case T.INT32:
                    val = pPointer.add(offset).readInt();
                    offset += 4;
                    break;
                case T.UINT32:
                    val = pPointer.add(offset).readU32();
                    offset += 4;
                    break;
                case T.LONG:
                    val = pPointer.add(offset).readLong();
                    offset += 8;
                    break;
                case T.ULONG:
                    val = pPointer.add(offset).readULong();
                    offset += 8;
                    break;
                case T.POINTER64:
                    val = pPointer.add(offset).readULong();
                    offset += 8;
                    break;

            }
            //console.log(JSON.stringify(fmt),val,i);
            v = this.parseValue( pContext, val, fmt, i);
            msg += ` \t${fmt.n} = ${v},${pSeparator}`;
        }

        return msg+pSeparator+" }";
    }

    /**
     *
     * @param pContext
     * @param pValue
     * @param pFormat
     * @param pIndex
     */
    parseValue( pContext:any, pValue:any, pFormat:any, pIndex:number):any {
        let p = "", rVal: any = null, data:any=null, t: any = null;


        if (typeof pFormat === "string") {
            p = pValue; //` ${pFormat} = ${pValue}`;
        } else {
            rVal = pValue;
            //p += ` ${pFormat.n} = `;


            switch (pFormat.l) {
                case L.DFD:
                    t = rVal.toInt32();
                    if (t >= 0)
                        p += `${t}  `;
                    else if (t == AT_.AT_FDCWD)
                        p += "AT_FDCWD "
                    else
                        p += rVal + " ERR?";
                    break;
                case L.MFD:
                    /*
                    Value of FD while mmap() depends of others args
                    todo : inject api into context to access current syscall data  : pContext.svc.mmap.flags
                     */
                    t = rVal.toInt32();
                    if (pContext.dxc.FD!=null && t >= 0)
                        p += `${t}  ${pContext.dxc.FD[rVal.toInt32() + ""]}  `;
                    else if ((t & MAP_.MAP_ANONYMOUS[0]) == MAP_.MAP_ANONYMOUS[0])
                        p += `${t} IGNORED  `
                    else
                        p += t + " ";
                    return;
                case L.FD:
                    t = rVal.toInt32();
                    if (pContext.dxc.FD!=null && t >= 0)
                        p += `${t}  ${pContext.dxc.FD[t + ""]}  `;
                    else if (t == AT_.AT_FDCWD)
                        p += "AT_FDCWD "
                    else
                        p += rVal + " ";
                    break;
                case L.SOCKFD:
                    t = rVal.toInt32();
                    if (pContext.dxc.SOCKFD!=null &&  t >= 0)
                        p += `${t}  ${pContext.dxc.SOCKFD[t + ""]}  `;
                    p += rVal + " ";
                    break;
                case L.WD:
                    t = rVal.toInt32();
                    if (pContext.dxc.WD!=null && t >= 0)
                        p += `${t}  ${pContext.dxc.WD[t + ""]}  `;
                        p += rVal + " ";
                    break;
                case L.VADDR:
                    if (pFormat.f == null) {
                        p += pContext.dxcOpts[pFormat] = rVal;
                        break;
                    }
                case L.FLAG:
                    if (pFormat.t != T.POINTER64){
                        data = rVal;
                    }else{
                        data = ptr(rVal); //readU64();
                    }

                    if (pFormat.r != null) {
                        if (Array.isArray(pFormat.r)) {
                            const t:number|string[] = [];
                            pFormat.r.map((x:number|string) => t.push(pContext[x]));
                            p += `${(pFormat.f)(rVal, t)}`;
                        } else {
                            p += `${(pFormat.f)(rVal, [pContext[pFormat.r]])}`;
                        }
                    } else {
                        p += `${(pFormat.f)(rVal)}`;
                    }
                    pContext.dxcOpts[pIndex] = rVal;
                    break;
                case L.DSTRUCT:
                    if(this.types!=null && this.types[pFormat.f] != null){
                        if (pContext.dxcOpts._extra == null) pContext.dxcOpts._extra = [];
                        pFormat.r = pIndex;
                        pFormat.v = rVal;
                        pContext.dxcOpts._extra.push(pFormat);
                        pContext.dxcOpts[pIndex] = rVal;

                        p += `${rVal} ${pFormat.c===true ? this.parseStruct( pContext, this.types[pFormat.f].getStruct(), pFormat.v, "" ) : ""}`;
                        break;
                    }
                default:
                    switch (pFormat.t) {
                        case T.STRING:
                            p += pContext.dxcOpts[pIndex] = rVal.readCString();
                            break;
                        case T.CHAR_BUFFER:
                            p += pContext.dxcOpts[pIndex] = rVal.readCString();
                            break;
                        case T.UINT32:
                        default:
                            p += pContext.dxcOpts[pIndex] = rVal;
                            break;
                    }
                    break;
            }
        }

        return p;
    }
    /**
     *
     * @param pContext
     * @param pFormat
     * @param pIndex
     */
    parseRawArgs( pContext:any, pFormat:any, pIndex:number):any {

        if (typeof pFormat === "string") {
            return` ${pFormat} = ${pContext[GPR + pIndex] }`;
        } else {
            return` ${pFormat.n} = ${this.parseValue( pContext, pContext[GPR + pIndex], pFormat, pIndex ) }`;
        }
    }

    traceSyscall( pContext:any, pHookCfg:any = null){

        const sys = SVC_MAP_NUM[ pContext.x8.toInt32() ];
        const inst = "SVC";

        if(sys==null) {
            console.log( ' ['+this.locatePC(pContext.pc)+']   \x1b[35;01m' + inst + ' ('+pContext.x8+')\x1b[0m Syscall=<unknow>');
            return;
        }

        pContext.dxcRET = sys[SVC_RET];

        let s = "", p= "";
        pContext.dxcOpts = [];
        sys[3].map((vVal,vOff) => {
            //const rVal = pContext["x"+vOff];
            p += ` ${this.parseRawArgs(pContext, vVal, vOff)} ,`;
        });
        s = `${sys[1]} ( ${p.slice(0,-1)} ) `;


        //console.log(s);
        if(this.output.flavor == InterruptorAgent.FLAVOR_DXC){
            pContext.log = this.formatLogLine(pContext, s, inst, pContext.x8)
        }

    }

    /**
     *
     * @param pContext
     * @param pSysc
     * @param pInst
     * @param pSysNum
     */
    formatLogLine( pContext:any, pSysc:string, pInst:string, pSysNum:number):string {
        let s = this.locatePC(pContext);
        s += this.output.inst ?  `   \x1b[35;01m${pInst} :: ${pSysNum} \x1b[0m` : "";
        s += `   ${pSysc}`;
        return s;
    }

    getSyscallError( pErrRet:number, pErrEnum:any[]):any {
        for(let i=0; i<pErrEnum.length ; i++){
            if(pErrRet === -pErrEnum[i][0] ){
                return pErrRet+' '+pErrEnum[i][2];
            }
        }
        return pErrRet;
    }

    traceSyscallRet( pContext:any, pHookCfg:any = null){


        let err;
        let ret = pContext.dxcRET;
        if(ret != null){

            switch (ret.l) {
                case L.SIZE:
                    if(this.output.dump_buff)
                        ret = "(len="+pContext.x0+") "; //+pContext["x"+ret.r].readCString();
                    else
                        ret = pContext.x0;
                    break;
                case L.DFD:
                case L.FD:
                    if(pContext.x0.toInt32() >= 0){
                        if(pContext.dxc==null){
                            pContext.dxc = {FD:{}};
                            pContext.dxcFD = pContext.dxc.FD = {};
                        }
                        if(pContext.dxc.FD==null){
                            pContext.dxcFD = pContext.dxc.FD = {};
                        }
                        pContext.dxc.FD[ pContext.x0.toInt32()+""] = pContext.dxcOpts[ret.r];
                        ret = "("+(L.DFD==ret.l?"D":"")+"FD) "+pContext.x0;
                    }else if(ret.e){
                        const err = this.getSyscallError(pContext.x0.toInt32(), ret.e);
                        ret = "(ERROR) "+err+" "  ;
                    }else{
                        ret = "(ERROR) "+pContext.x0;
                    }

                    break;
                case L.SOCKFD:
                    if(pContext.x0.toInt32() >= 0){
                        pContext.dxc.SOCKFD[ pContext.x0.toInt32()+""] = pContext.dxcOpts["x1"]+","+pContext.dxcOpts["x2"];
                        ret = "(SOCKFD) "+pContext.x0;
                    }else if(ret.e){
                        const err = this.getSyscallError(pContext.x0.toInt32(), ret.e);
                        ret = "(ERROR) "+err+" "  ;
                    }else{
                        ret = "(ERROR) "+pContext.x0;
                    }
                case L.WD:
                    if(pContext.x0.toInt32() >= 0){
                        pContext.dxc.WD[ pContext.x0.toInt32()+""] = pContext.dxcOpts[ret.r];
                        ret = "(WD) "+pContext.x0;
                    }else if(ret.e){
                        const err = this.getSyscallError(pContext.x0.toInt32(), ret.e);
                        ret = "(ERROR) "+err+" "  ;
                    }else{
                        ret = "(ERROR) "+pContext.x0;
                    }

                    break;
                case L.FCNTL_RET:
                    ret = X.FCNTL_RET(pContext.x0, pContext.x1);
                    break;
                case L.VADDR:
                    if(ret.e != null ){
                        err = this.getSyscallError(pContext.x0, ret.e);
                        if(err != pContext.x0){
                            ret = pContext.x0+' SUCCESS';
                        }else{
                            ret = err ;
                        }
                    }
                    break;
                default:
                    if(ret.e != null ){
                        err = this.getSyscallError(pContext.x0.toInt32(), ret.e);
                        if(err == 0){
                            ret = pContext.x0.toUInt32().toString(16)+' SUCCESS';
                        }else{
                            ret = err ;
                        }
                    }
                    else
                        ret = pContext.x0.toUInt32().toString(16);
                    break;
            }
        }else{
           ret = pContext.x0;
        }

        // main print here
        console.log( pContext.log +'   > '+ret);

        // to process extra data such as structured data edited or passed as args
        if(pContext.dxcOpts != null && pContext.dxcOpts._extra){
            pContext.dxcOpts._extra.map( (x:any) => {

                console.log(` ${x.n} = `+this.parseStruct(
                    pContext,
                    this.types[x.f].getStruct(),
                    (x.v != null ?
                        // if the pointer has been saved before to call the syscall, then it uses saved value
                        x.v :
                        // if the register holding the pointer has been modified by the syscall, then it read register value
                        pContext.dxcOpts[x.r] )
                ));
            });
        }

    }


    trace( pStalkerInterator: StalkerX86Iterator
        | StalkerArm64Iterator
        | StalkerArmIterator
        | StalkerThumbIterator, pInstruction:any, pExtra:any):number{


        const self = this as any;

        const keep = 1;
        if(pExtra.onLeave == 1){

            pStalkerInterator.putCallout((context: PortableCpuContext) =>{

                const richCtx = context as RichArm64CpuContext;
                const n = richCtx.x8.toInt32();

                if(richCtx.dxc==null) richCtx.dxc = {FD:{}};
                if(this.scope.syscalls!=null && this.scope.syscalls.isExcluded!=null && this.scope.syscalls.isExcluded(n)) return;

                //self.traceSyscallRet(context);

                if(this.debug.syscallLookup){
                    console.log(`[DEBUG][SYSCALL][${richCtx.dxc.orig}][${n}] BEFORE ret Parsing}`);
                }
                this.traceSyscallRet(richCtx);
                if(this.debug.syscallLookup){
                    console.log(`[DEBUG][SYSCALL][${richCtx.dxc.orig}][${n}] AFTER ret Parsing}`);
                }

                const hook = this.svc_hk[n];
                if(hook == null) return ;

                if(hook.onLeave != null){
                    (hook.onLeave)(richCtx);
                }
            });

            pExtra.onLeave = null;
        }

        const m = Process.findModuleByAddress(pInstruction.address)

        // debug
        if(this.debug.stalker){
            console.log("["+pInstruction.address+" : "+m.name+" "+(pInstruction.address.sub(m.base))+"] > "+Instruction.parse(pInstruction.address));
        }


        if (pInstruction.mnemonic === 'svc') {

            pExtra.onLeave =  1;
            pStalkerInterator.putCallout((context: PortableCpuContext) =>{

                const richCtx = context as RichArm64CpuContext;
                const n = richCtx.x8.toInt32();

                const m = Process.findModuleByAddress(context.pc)

                // debug
                if(this.debug.syscallLookup){
                    if(m!=null) {
                        console.log("[DEBUG][SYSCALL][BEFORE FILTER][" + context.pc + " : " + m.name + " " + (context.pc.sub(m.base)) + "] > " + Instruction.parse(context.pc) + " > NUM " + n);
                    }else{
                        console.log("[DEBUG][SYSCALL][BEFORE FILTER][" + context.pc + " : UNKNOW MODULE " + (context.pc)+" - MODULE_BASE ] > " + Instruction.parse(context.pc) + " > NUM " + n);
                    }
                }


                //if(isExcludedFn!=null && isExcludedFn(n)) return;
                //f(this.scope.syscalls.isExcluded!=null && this.scope.syscalls.isExcluded(n)) return;
                if(this.scope.syscalls!=null && this.scope.syscalls.isExcluded!=null && this.scope.syscalls.isExcluded(n)) return;

                if(richCtx.dxc==null) richCtx.dxc = {FD:{}};
                const hook = this.svc_hk[n];

                richCtx.dxc.orig = context.pc;

                if(hook != null && hook.onEnter != null){
                    (hook.onEnter)(richCtx);
                }


                if(this.debug.syscallLookup){
                    console.log(`[DEBUG][SYSCALL][${richCtx.dxc.orig}][${n}] BEFORE arg Parsing}`);
                }
                this.traceSyscall(richCtx, hook);
                if(this.debug.syscallLookup){
                    console.log(`[DEBUG][SYSCALL][${richCtx.dxc.orig}][${n}] AFTER arg Parsing = \n\t${richCtx.log }`);
                }
            });
        }

        return keep;
    }

    printStats(){
        super.printStats(SVC);
    }
}