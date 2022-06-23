import {F, InterruptorAgent} from "../common/InterruptorAgent";
import {InterruptorGenericException} from "../common/InterruptorException";
import {T,L} from "../common/Types";
import * as DEF from "./LinuxX64Flags";
import {TypedData} from "../common/TypedData";
import {SYSC} from "./LinuxX64Syscalls";

// GPR = Global Purpose Register prefix => x/r
const GPR = "e";
const SYSC_NUM = 0;
const SYSC_NAME = 1;
const SYSC_ARG = 3;
const SYSC_RET = 4;
const SVC_ERR = 5;

//{AT_, E, MAP_, X}
const AT_ = DEF.AT_;
const MAP_ = DEF.MAP_;
const X = DEF.X;

// Calling Convention
const CC = {
    OP: 'syscall',
    NR: 'rax',
    RET: 'rax',
    ARG0: 'rdi',
    ARG1: 'rsi',
    ARG2: 'rdx',
    ARG3: 'r10',
    ARG4: 'r8',
    ARG5: 'r9',
};


const SYSC_MAP_NUM:any = {};
const SYSC_MAP_NAME:any = {};

SYSC.map(x => {
    SYSC_MAP_NAME[x[1] as string] = x;
    SYSC_MAP_NUM[x[0] as string] = x;
});

let isExcludedFn:any = null;

export const KAPI = {
    CONST: DEF,
    SVC: SYSC_MAP_NAME,
    SVC_ARG: SYSC_ARG,
    ERR: DEF.ERR
};

export class LinuxX64InterruptorAgent extends InterruptorAgent{

    loadCtr:number = 0;

    filter_name: string[] = [];
    filter_num: string[] = [];
    svc_hk: any = {};

    constructor(pConfig:any, pDoFollowThread:any) {
        super(pConfig, pDoFollowThread);
        this.configure(pConfig);
    }

    /**
     * To extend common filters
     *
     * @param pTypes
     * @param pOpts
     */
    _setupDelegateFilters( pTypes:string, pOpts:any):void {
        if(pOpts == null) return;

        const o = pOpts;
        const f = this[pTypes];

        ["svc"].map( x => {
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
                SYSC.map( x => { if(x[1]==pSyscalls) list.push(x[SYSC_NUM]); });
                break;
            case "function":
                SYSC.map( x => { if(pSyscalls.apply(null, x)) list.push(x[SYSC_NUM]); });
                break;
            case "object":
                if(Array.isArray(pSyscalls)){
                    pSyscalls.map( sVal => {
                        switch(typeof sVal){
                            case "string":
                                SYSC.map( x => { if(x[SYSC_NAME]==sVal) list.push(x[SYSC_NUM]); });
                                break;
                            case "number":
                                SYSC.map( x => { if(x[SYSC_NUM]==sVal) list.push(x[SYSC_NUM]); });
                                break;
                            case "object":
                                SYSC.map( x => { if(sVal.exec(x[SYSC_NAME])!=null) list.push(x[SYSC_NUM]); });
                                break;
                        }
                    })
                }else if (pSyscalls instanceof RegExp){
                    SYSC.map( x => { if(pSyscalls.exec(x[1])!=null) list.push(x[0]); });
                }else{
                    SYSC.map(x => { list.push(x[SYSC_NUM]); });
                }
                break;
            default:
                SYSC.map(x => { list.push(x[SYSC_NUM]); });
                break;
        }

        return list;
    }

    onSupervisorCall(pIntName:string, pHooks:any){
        const sc = SYSC_MAP_NAME[pIntName];
        if(sc == null) throw InterruptorGenericException.UNKNOW_SYSCALL(pIntName);
        if(pHooks.hasOwnProperty('onEnter') || pHooks.hasOwnProperty('onLeave')){
            this.svc_hk[sc[0]] = pHooks
        }

    }

    /*
    //
    onHypervisorCall(pIntNum:number, pHooks:any){
        // Hypervisor call are not implemented for x86
    }

     */

    setupBuiltinHook(){
    }

    locateRIP( pContext: any):string{
        let l = "", tid:number =-1;

        const r = Process.findRangeByAddress(pContext.rip);

        if(this.output.tid) {
            tid = Process.getCurrentThreadId();
            l += `\x1b[1;${this.output._tcolor}m [TID=${tid}] \x1b[0m`;

        }

        if(this.output.module){
            if(r != null){
                if(r.file != null){
                    if(this.output.hide!=null){
                        l +=  `[${ r.file.path.replace(this.output.hide, "HIDDEN")} +${pContext.rip.sub(r.base)}]`;
                    }else{
                        l +=  `[${ r.file.path } +${pContext.rip.sub(r.base)}]`;
                    }
                }else{
                    l +=  `[${r.base} +${pContext.rip.sub(r.base)}]`;
                }
            }else{
                l += `[<unknow>  rip=${pContext.rip}]`;
            }
        }

        if(this.output.lr)
            l += `[lr=${pContext.rip}]`;

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
            return` ${pFormat} = ${pContext[ CC['ARG'+pIndex] ] }`;
        } else {
            return` ${pFormat.n} = ${this.parseValue( pContext, pContext[ CC['ARG'+pIndex] ], pFormat, pIndex ) }`;
        }
    }

    traceSyscall( pContext:any, pHookCfg:any = null){

        const sysNR = pContext[CC.NR];
        const sysSignature = SYSC_MAP_NUM[ sysNR.toInt32() ];

        if(sysSignature==null) {
            console.log( ' ['+this.locateRIP(pContext)+']   \x1b[35;01m' + CC.OP + ' ('+sysNR+')\x1b[0m =<unknow>');
            return;
        }

        pContext.dxcRET = sysSignature[SYSC_RET];

        let s:string = "", p:string= "";
        pContext.dxcOpts = [];
        sysSignature[3].map((vVal,vOff) => {
            p += ` ${this.parseRawArgs(pContext, vVal, vOff)} ,`;
        });
        s = `${sysSignature[1]} ( ${p.slice(0,-1)} ) `;

        if(this.output.flavor == InterruptorAgent.FLAVOR_DXC){
            pContext.log = this.formatLogLine(pContext, s, CC.OP, sysNR)
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
        let s = this.locateRIP(pContext);
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
        let retReg:any = null;

        if(ret != null){

            retReg = pContext[CC.RET];

            switch (ret.l) {
                case L.SIZE:
                    if(this.output.dump_buff)
                        ret = "(len="+retReg+") "; //+pContext["x"+ret.r].readCString();
                    else
                        ret = retReg;
                    break;
                case L.DFD:
                case L.FD:
                    if(retReg.toInt32() >= 0){
                        if(pContext.dxc==null){
                            pContext.dxc = {FD:{}};
                            pContext.dxcFD = pContext.dxc.FD = {};
                        }
                        if(pContext.dxc.FD==null){
                            pContext.dxcFD = pContext.dxc.FD = {};
                        }
                        pContext.dxc.FD[ retReg.toInt32()+""] = pContext.dxcOpts[ret.r];
                        ret = "("+(L.DFD==ret.l?"D":"")+"FD) "+retReg;
                    }else if(ret.e){
                        let err = this.getSyscallError(retReg.toInt32(), ret.e);
                        ret = "(ERROR) "+err+" "  ;
                    }else{
                        ret = "(ERROR) "+retReg;
                    }

                    break;
                case L.SOCKFD:
                    if(retReg.toInt32() >= 0){
                        pContext.dxc.SOCKFD[ retReg.toInt32()+""] = pContext.dxcOpts["x1"]+","+pContext.dxcOpts["x2"];
                        ret = "(SOCKFD) "+retReg;
                    }else if(ret.e){
                        let err = this.getSyscallError(retReg.toInt32(), ret.e);
                        ret = "(ERROR) "+err+" "  ;
                    }else{
                        ret = "(ERROR) "+retReg;
                    }
                case L.WD:
                    if(retReg.toInt32() >= 0){
                        pContext.dxc.WD[ retReg.toInt32()+""] = pContext.dxcOpts[ret.r];
                        ret = "(WD) "+retReg;
                    }else if(ret.e){
                        let err = this.getSyscallError(retReg.toInt32(), ret.e);
                        ret = "(ERROR) "+err+" "  ;
                    }else{
                        ret = "(ERROR) "+retReg;
                    }

                    break;
                case L.FCNTL_RET:
                    ret = X.FCNTL_RET(retReg, pContext[CC.ARG0]);
                    break;
                case L.VADDR:
                    if(ret.e != null ){
                        err = this.getSyscallError(retReg, ret.e);
                        if(err != retReg){
                            ret = retReg+' SUCCESS';
                        }else{
                            ret = err ;
                        }
                    }
                    break;
                default:
                    if(ret.e != null ){
                        err = this.getSyscallError(retReg.toInt32(), ret.e);
                        if(err == 0){
                            ret = retReg.toUInt32().toString(16)+' SUCCESS';
                        }else{
                            ret = err ;
                        }
                    }
                    else
                        ret = retReg.toUInt32().toString(16);
                    break;
            }
        }else{
           ret =  pContext[CC.RET];
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
                const n = context[CC.NR].toInt32();

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
//        console.log("["+pInstruction.address+" : "+pInstruction.address.sub(pExtra.mod.__mod.base)+"] > "+Instruction.parse(pInstruction.address));
        //console.log("["+pInstruction.address+"] > "+Instruction.parse(pInstruction.address));

        if (pInstruction.mnemonic === CC.OP) {

            //console.log("SVC Found : > "+pInstruction.mnemonic);
            pExtra.onLeave =  1;
            pStalkerInterator.putCallout(function(context) {

                const n = context[CC.NR].toInt32();

                if(isExcludedFn!=null && isExcludedFn(n)) return;

                if(context.dxc==null) context.dxc = {FD:{}};
                const hook = self.svc_hk[n];


                if(hook != null && hook.onEnter != null) (hook.onEnter)(context);

                self.traceSyscall(context, hook);

            });
        }

        return keep;
    }
}