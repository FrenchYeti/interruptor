import {F, InterruptorAgent} from "../common/InterruptorAgent";
import {InterruptorGenericException} from "../common/InterruptorException";
import {T,L} from "../common/Types";
import * as DEF from "../kernelapi/LinuxArm64Flags";
import {TypedData} from "../common/TypedData";
import {SVC} from "../syscalls/LinuxAarch64Syscalls";

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

const SVC_MAP_NUM:any = {};
const SVC_MAP_NAME:any = {};

SVC.map(x => {
    SVC_MAP_NAME[x[1] as string] = x;
    SVC_MAP_NUM[x[0] as string] = x;
});

let isExcludedFn:any = null;

export const KAPI = {
    CONST: DEF,
    SVC: SVC_MAP_NAME,
    SVC_ARG: SVC_ARG,
    ERR: DEF.ERR
};

export class LinuxArm64InterruptorAgent extends InterruptorAgent{

    loadCtr:number = 0;

    filter_name: string[] = [];
    filter_num: string[] = [];
    svc_hk: any = {};
    hvc_hk: any = {};
    smc_hk: any = {};
    irq_hk: any = {};

    constructor(pConfig:any, pDoFollowThread:any) {
        super(pConfig, pDoFollowThread);
        this.configure(pConfig);
    }

    _setupDelegateFilters( pTypes:string, pOpts:any):void {
        if(pOpts == null) return;

        const o = pOpts;
        const f = this[pTypes];

        ["svc","hvc","smc"].map( x => {
            if(o.hasOwnProperty(x))
                f[x] = o[x];
        });

        if(f.hasOwnProperty("syscalls") && f.syscalls != null){
            f.svc = this.getSyscallList(f.syscalls);
        }
    }

    configure(pConfig:any){
        if(pConfig == null) return;

        for(let k in pConfig){
            switch (k){
                case 'svc':
                    for(let s in pConfig.svc) this.onSupervisorCall(s, pConfig.svc[s]);
                    break;
                case 'hvc':
                    for(let s in pConfig.hvc) this.onHypervisorCall( parseInt(s as any, 16), pConfig.hvc[s]);
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

    protected _updateScope(pScope:any):void {
        switch ( this._policy.svc){
            case F.INCLUDE_ANY:
                isExcludedFn = (x)=>{ return (this._scope.svc.indexOf(x)>-1); };
                break;
            case F.EXCLUDE_ANY:
                isExcludedFn = (x)=>{ return (this._scope.svc.indexOf(x)==-1);};
                break;
            case F.FILTER:
                isExcludedFn = (x)=>{ return (this._scope.svc.i.indexOf(x)==-1 || this._scope.svc.e.indexOf(x)>-1);};
                break;
        }
    }

    /**
     * To generate a filtered list of syscalls
     * @param {string[]} pSyscalls An array of syscall number
     * @method
     */
    getSyscallList( pSyscalls:any ):any {

        const list = [];

        switch(typeof pSyscalls){
            case "string":
                SVC.map( x => { if(x[1]==pSyscalls) list.push(x[SVC_NUM]); });
                break;
            case "function":
                SVC.map( x => { if(pSyscalls.apply(null, x)) list.push(x[SVC_NUM]); });
                break;
            case "object":
                if(Array.isArray(pSyscalls)){
                    pSyscalls.map( sVal => {
                        switch(typeof sVal){
                            case "string":
                                SVC.map( x => { if(x[SVC_NAME]==sVal) list.push(x[SVC_NUM]); });
                                break;
                            case "number":
                                SVC.map( x => { if(x[SVC_NUM]==sVal) list.push(x[SVC_NUM]); });
                                break;
                            case "object":
                                SVC.map( x => { if(sVal.exec(x[SVC_NAME])!=null) list.push(x[SVC_NUM]); });
                                break;
                        }
                    })
                }else if (pSyscalls instanceof RegExp){
                    SVC.map( x => { if(pSyscalls.exec(x[1])!=null) list.push(x[0]); });
                }else{
                    SVC.map(x => { list.push(x[SVC_NUM]); });
                }
                break;
            default:
                SVC.map(x => { list.push(x[SVC_NUM]); });
                break;
        }

        return list;
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
    }

    locatePC( pContext: any):string{
        let l = "", tid:number =-1;
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
        let self=this, do_dlopen = null, call_ctor = null, scopedTrace = null, extra = null, match=null;
        //let opts = pOptions;
        Process.findModuleByName('linker64').enumerateSymbols().forEach(sym => {
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


        Interceptor.attach(do_dlopen, function (args) {
            const p = args[0].readUtf8String();

            if(p!=null && pModuleRegExp.exec(p) != null){
                match = p;
            }
        });

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
    parseStruct( pContext:any, pFormats:TypedData[], pPointer:NativePointer, pSeparator:string ="\n", pAlign:boolean = false):string {

        let msg:string = " {"+pSeparator;
        let fmt:TypedData = null, v:string = "", val:any = null;
        let offset:number =0;

        //console.log("DSTRUCT",JSON.stringify(pFormats));

        for(let i=0; i<pFormats.length; i++){
            fmt = pFormats[i];
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
        let p: string = "", rVal: any = null, t: any = null;


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
                    if (pFormat.r != null) {
                        if (Array.isArray(pFormat.r)) {
                            let t = [];
                            pFormat.r.map(x => t.push(pContext[x]));
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
        let inst = "SVC";

        if(sys==null) {
            console.log( ' ['+this.locatePC(pContext.pc)+']   \x1b[35;01m' + inst + ' ('+pContext.x8+')\x1b[0m Syscall=<unknow>');
            return;
        }

        pContext.dxcRET = sys[SVC_RET];

        let s:string = "", p:string= "";
        pContext.dxcOpts = [];
        sys[3].map((vVal,vOff) => {
            //const rVal = pContext["x"+vOff];
            p += ` ${this.parseRawArgs(pContext, vVal, vOff)} ,`;
        });
        s = `${sys[1]} ( ${p.slice(0,-1)} ) `;

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
        let post:string = null;
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
                        let err = this.getSyscallError(pContext.x0.toInt32(), ret.e);
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
                        let err = this.getSyscallError(pContext.x0.toInt32(), ret.e);
                        ret = "(ERROR) "+err+" "  ;
                    }else{
                        ret = "(ERROR) "+pContext.x0;
                    }
                case L.WD:
                    if(pContext.x0.toInt32() >= 0){
                        pContext.dxc.WD[ pContext.x0.toInt32()+""] = pContext.dxcOpts[ret.r];
                        ret = "(WD) "+pContext.x0;
                    }else if(ret.e){
                        let err = this.getSyscallError(pContext.x0.toInt32(), ret.e);
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

        console.log( pContext.log +'   > '+ret);

        // to process extra data such as structured data edited or passed as args
        if(pContext.dxcOpts != null && pContext.dxcOpts._extra){
            pContext.dxcOpts._extra.map( x => {

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


    trace( pStalkerInterator:any, pInstruction:any, pExtra:any):number{


        const self = this;

        let keep = 1;
        if(pExtra.onLeave == 1){

            pStalkerInterator.putCallout(function(context) {
                const n = context.x8.toInt32();
                if(context.dxc==null) context.dxc = {FD:{}};
                if(isExcludedFn!=null && isExcludedFn(n)) return;

                self.traceSyscallRet(context);

                const hook = self.svc_hk[n];
                if(hook == null) return ;

                if(hook.onLeave != null){
                    (hook.onLeave)(context);
                }
            });

            pExtra.onLeave = null;
        }

        // debug
        //console.log("["+pInstruction.address+" : "+pInstruction.address.sub(pExtra.mod.__mod.base)+"] > "+Instruction.parse(pInstruction.address));

        if (pInstruction.mnemonic === 'svc') {

            //console.log("SVC Found : > "+pInstruction.mnemonic);
            pExtra.onLeave =  1;
            pStalkerInterator.putCallout(function(context) {

                const n = context.x8.toInt32();

                if(isExcludedFn!=null && isExcludedFn(n)) return;

                if(context.dxc==null) context.dxc = {FD:{}};
                const hook = self.svc_hk[n];


                if(hook != null && hook.onEnter != null) (hook.onEnter)(context);

                self.traceSyscall(context, hook);

            });
        }

        return keep;
    }

    printStats(){
        super.printStats(SVC);
    }
}