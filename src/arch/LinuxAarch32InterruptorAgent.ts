import {InterruptorAgent, InterruptorAgentConfig, StartOnLoadOpts} from "../common/InterruptorAgent.js";
import {InterruptorGenericException} from "../common/InterruptorException.js";
import {
    T,
    L,
    SyscallCallingConvention,
    SyscallInfo,
    SyscallParamSignature,
    RichCpuContext, SyscallMapping
} from "../common/Types.js";
import * as DEF from "../kernelapi/LinuxArm64Flags.js";
import {TypedData} from "../common/TypedData.js";
import {SWI} from "../syscalls/LinuxAarch32Syscalls.js";
import {IStringIndex} from "../utilities/IStringIndex.js";
import {KernelAPI, KernelEnum} from "../kernelapi/Types.js";

function printBackTrace(pContext:any):void {
    console.log(Thread.backtrace(pContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
}

function printCpuContext(ctx:any){

    console.log(`
    \x1b[1; 
\tr0=${ctx.r0}
\tr1=${ctx.r1} \t r2=${ctx.r2} \t r3=${ctx.r3} 
\tr4=${ctx.r4} \t r5=${ctx.r5} \t r6=${ctx.r6} 
\tr7=${ctx.r7} \t pc=${ctx.pc} \t lp=${ctx.lp} 
    \x1b[0m 
    `);


}
//{AT_, E, MAP_, X}
const AT_ = DEF.CONSTANTS.AT_ as KernelEnum;
const MAP_ = DEF.CONSTANTS.MAP_ as KernelEnum;
const X = DEF.X;

// Syscall calling Convention for aarch32
const CC:SyscallCallingConvention = {
    OP: 'swi', // swi
    NR: 'r7',
    RET: 'r0',
    ARG0: 'r0',
    ARG1: 'r1',
    ARG2: 'r2',
    ARG3: 'r3',
    ARG4: 'r4',
    ARG5: 'r5',
    PC: 'pc'
};


interface RichContextOptions extends ArmCpuContext {
    _extra?:any;
    [name:string] :any;
}

interface RichArmCpuContext extends RichCpuContext, ArmCpuContext, IStringIndex {
    dxcOpts?:RichArmCpuContext;
}


const SYSC_MAP_NUM:any = {};
const SYSC_MAP_NAME:SyscallMapping = {};

const SO_LOADED:any = {};

SWI.map(x => {
    SYSC_MAP_NAME[x[1]] = x;
    SYSC_MAP_NUM[x[0]] = x;
});

export const KAPI:KernelAPI = {
    CONST: DEF.CONSTANTS,
    SYSC: SYSC_MAP_NAME,
    ERR: DEF.ERR
};


export interface LinuxAarch32InterruptorAgentConfig extends InterruptorAgentConfig {
    catchWFI?:boolean;
    catchBRK?:boolean;
    catchOP?:string[];
    svc?:any;
    hvc?:any;
    filter_name?:any;
    filter_num?:any;
}


export class LinuxAarch32InterruptorAgent extends InterruptorAgent implements IStringIndex{

    loadCtr:number = 0;

    /*
     * TODO: Catch WaitForInterruption, bkpt, ..
     */
    catchWFI:boolean = false;
    catchBKPT:boolean = false;

    catchOP:string[] = [];

    filter_name: string[] = [];
    filter_num: string[] = [];
    svc_hk: any = {};

    __match:string|null=null;
    __callconst_called = false;
    __started = false;

    constructor(pConfig:LinuxAarch32InterruptorAgentConfig, pDoFollowThread:any) {
        super(pConfig, pDoFollowThread);
        this.configure(pConfig);
    }

    /**
     * To extend common filters
     *
     * @param pTypes
     * @param pOpts
     */
    /*
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
    }*/

    configure(pConfig:any){
        if(pConfig == null) return;

        for(let k in pConfig){
            switch (k){
                case 'catchOP':
                    this.catchOP = pConfig.catchOP;
                    break;
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



    /*
     * To generate a filtered list of syscalls
     * @param {string[]} pSyscalls An array of syscall number
     * @method
     */
    /*
    getSyscallList( pSyscalls:any ):any {

        const list = [];

        switch(typeof pSyscalls){
            case "string":
                SWI.map( x => { if(x[1]==pSyscalls) list.push(x[SYSC_NUM]); });
                break;
            case "function":
                SWI.map( x => { if(pSyscalls.apply(null, x)) list.push(x[SYSC_NUM]); });
                break;
            case "object":
                if(Array.isArray(pSyscalls)){
                    pSyscalls.map( sVal => {
                        switch(typeof sVal){
                            case "string":
                                SWI.map( x => { if(x[SYSC_NAME]==sVal) list.push(x[SYSC_NUM]); });
                                break;
                            case "number":
                                SWI.map( x => { if(x[SYSC_NUM]==sVal) list.push(x[SYSC_NUM]); });
                                break;
                            case "object":
                                SWI.map( x => { if(sVal.exec(x[SYSC_NAME])!=null) list.push(x[SYSC_NUM]); });
                                break;
                        }
                    })
                }else if (pSyscalls instanceof RegExp){
                    SWI.map( x => { if(pSyscalls.exec(x[1])!=null) list.push(x[0]); });
                }else{
                    SWI.map(x => { list.push(x[SYSC_NUM]); });
                }
                break;
            default:
                SWI.map(x => { list.push(x[SYSC_NUM]); });
                break;
        }

        return list;
    }*/

    onSupervisorCall(pIntName:string, pHooks:any){
        const sc = SYSC_MAP_NAME[pIntName];
        if(sc == null) throw InterruptorGenericException.UNKNOW_SYSCALL(pIntName);
        if(pHooks.hasOwnProperty('onEnter') || pHooks.hasOwnProperty('onLeave')){
            this.svc_hk[sc[0]] = pHooks
        }

    }

    setupBuiltinHook(){
    }

    locatePC( pContext: any):string{
        let l = "", tid:number =-1;

        const regPC = pContext[CC.PC];
        const r = Process.findRangeByAddress(regPC);

        if(this.output.tid) {
            tid = Process.getCurrentThreadId();
            l += `\x1b[1;${this.output._tcolor}m [TID=${tid}] \x1b[0m`;

        }

        if(this.output.module){
            if(r != null){
                if(r.file != null){
                    if(this.output.hide!=null){
                        l +=  `[${ r.file.path.replace(this.output.hide, "HIDDEN")} +${regPC.sub(r.base)}]`;
                    }else{
                        l +=  `[${ r.file.path } +${regPC.sub(r.base)}]`;
                    }
                }else{
                    l +=  `[${r.base} +${regPC.sub(r.base)}]`;
                }
            }else{
                l += `[<unknow>  pc=${regPC}]`;
            }
        }

        if(this.output.lr)
            l += `[lr=${regPC}]`;

        return l;
    }

    startOnLoad( pModuleRegExp:RegExp, pOptions:StartOnLoadOpts = {}):any {
        let self=this;
        let do_dlopen:NativePointer = null, call_ctor:NativePointer = null, scopedTrace:NativePointer[] = [];
        let extra:any = null;
        let libcformatbuffer = null;
        let libcformatlog = null;
        let callfunc = null;
        let callarr = null;
        let dlsym = null;
        let match:string=null;
        let callconst_called=false;
        let callarr_called=false;

        console.log("Base address = "+Process.findModuleByName('linker').base )
        //let opts = pOptions;
        Process.findModuleByName('linker').enumerateSymbols().forEach(sym => {
/*
            if(sym.type==="function"){
                console.log(JSON.stringify(sym));
            }
*/
            if (sym.name.indexOf('do_dlopen') >= 0) {
                do_dlopen = sym.address;
            } else if (sym.name.indexOf('call_constructor') >= 0) {
                call_ctor = sym.address;
            } else if (sym.name.indexOf("call_function")>= 0){
                callfunc = sym.address
            }/* else if (sym.name.indexOf("call_array")>= 0){
                callarr = sym.address
            } /* else if (sym.name.indexOf("__dl_dlsym")>= 0){
                dlsym = sym.address;
            }  else if (sym.name.indexOf("__dl___libc_format_buffer")>= 0){
                libcformatbuffer = sym.address
            } else if (sym.name.indexOf("__dl___libc_format_log")>= 0){
                libcformatlog = sym.address
            } /*else if (sym.name.indexOf("call_function")>= 0){
                callfunc = sym.address
            } else if(sym.name.indexOf('__dl__ZN11ScopedTrace3EndEv') >= 0){
                scopedTrace.push(sym.address);
            } else if(sym.name.indexOf('__dl__ZL24debuggerd_signal_handleriP7siginfo')>=0){
                scopedTrace.push(sym.address);
            }*/
        });

        if(libcformatbuffer!=null){
            console.log("__dl___libc_format_buffer found at "+libcformatbuffer)
            Interceptor.attach(libcformatbuffer, {
                onEnter: function(args){
                    const msg = args[2].readUtf8String();
                    const argn = msg.split('%');
                    let fmtargs = "";
                    if(argn.length>1){
                        for(let i=1; i<argn.length; i++){
                            if(argn[i][0]==='s')
                                fmtargs+= i+"="+(this.context as any)['r'+(2+i)].readCString()+", ";
                            else
                                fmtargs+= i+"="+(this.context as any)['r'+(2+i)]+", ";
                        }
                    }

                    console.log("[LINKER] fmt buffer "+args[2].readUtf8String()+" "+fmtargs); //.readUtf8String())
                    //printBackTrace(this.context);
                    //printCpuContext(this.context);
                }
            })
        }

        if(libcformatlog!=null){
            console.log("__dl___libc_format_log found")
            Interceptor.attach(libcformatlog, {
                onEnter: function(args){
                    let msg = args[2].readUtf8String();
                    //printBackTrace(this.context);
                    console.log("[LINKER] log> "+args[1]+" :: "+msg);
                }
            })
        }

        if(callarr!=null){
            console.log("callarr found")
            Interceptor.attach(callarr, {
                onEnter: function(args){
                    let msg = args[1].readUtf8String();
                    console.log("[LINKER] callarr>  "+msg);
                }
            })
        }

        if(callfunc!=null){
            console.log("callfunc found")
            Interceptor.attach(callfunc, {
                onEnter: function(args){

                    console.log("[LINKER] callfunc> "+args[1].readCString());
                    if((self.__match !== null) && (self.__callconst_called===true) && (args[1].readCString()=="DT_INIT")){

                        self.__callconst_called = false;

                        console.warn("Start hooks");
                        const tmp = self.__match;

                        console.warn("[LINKER] Loading '"+self.__match+"'");
                        if(pOptions!=null && pOptions.hasOwnProperty('condition')){
                            if(!pOptions.condition(self.__match, this)){
                                self.__match = null;
                                return ;
                            }
                        }

                        console.warn("[INTERRUPTOR][STARTING] Module '"+self.__match+"' is loading, tracer will start");
                        self.__match = null;

                        if(self.__started===false){
                            self.__started = true;
                            self.start();

                            if(pOptions!=null && pOptions.hasOwnProperty('threshold')){
                                console.log(self.loadCtr, pOptions.threshold)
                                if(self.loadCtr < pOptions.threshold){
                                    self.loadCtr++;
                                    self.onStart( tmp, this);
                                }else{
                                    console.warn("[INTERRUPTOR][STARTING] Threshold reached");
                                }
                            }else{
                                self.onStart( tmp, this);
                            }
                        }else{
                            console.warn("[INTERRUPTOR][STARTING] Skipped.");
                        }



                    }
                }
            })
        }

        //console.log("\ndl_open = "+do_dlopen+"\ncall_ctor = "+call_ctor+"\n _scopedTrace ="+scopedTrace.join(':'));

        if(this.emulator && scopedTrace.length>0){
            do {
                const ptr = scopedTrace.pop();
                Interceptor.replace(ptr,  new NativeCallback(():number=>{
                    console.log("[EMULATOR MODE] Mock of __dl__ZL24debuggerd_signal_handleriP7siginfo  executed");
                    return 1;
                }, 'int', ['int']));
            }while (scopedTrace.length > 0);
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



        Interceptor.attach(do_dlopen, {
            onEnter: function (args) {
                const p = args[0].readUtf8String();

                if(p!=null && pModuleRegExp.exec(p) != null){
                    self.__match = p;
                    //SO_LOADED[p] = false;
                    console.log("[LINKER][DO_DLOPEN]["+this.context.pc+"] + "+p);
                }else{
                    console.log("[LINKER][DO_DLOPEN]["+this.context.pc+"] - "+p);
                }


            }
        });

        Interceptor.attach(call_ctor, {
            onEnter:function () {

                if(self.__match!==null && self.__match.length>0){
                    console.log("[LINKER][CALL_CTOR]["+this.context.pc+"] for "+self.__match);
                    self.__callconst_called = true;
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
    parseValue( pContext:any, pValue:any, pFormat:SyscallParamSignature, pIndex:number):any {
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
                        p += (pContext.dxcOpts[pFormat.n] = rVal);
                        break;
                    }
                    break;
                case L.FLAG:
                    if (pFormat.r != null) {
                        if (Array.isArray(pFormat.r)) {
                            let t:NativePointer[] = [];
                            pFormat.r.map((x:string|number) => {
                                if(x==null) return;

                                if(typeof x==="string")
                                    t.push(pContext[x])
                                else
                                    t.push(pContext["r"+x])
                            });
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
    parseRawArgs( pContext:any, pFormat:SyscallParamSignature, pIndex:number):any {

        if (typeof pFormat === "string") {
            return` ${pFormat} = ${pContext[ CC['ARG'+pIndex] as string ] }`;
        } else {
            return` ${pFormat.n} = ${this.parseValue( pContext, pContext[ CC['ARG'+pIndex] ], pFormat, pIndex ) }`;
        }
    }

    traceSyscall( pContext:any, pHookCfg:any = null){

        const sysNR = pContext[CC.NR];
        const sysSignature = SYSC_MAP_NUM[ sysNR.toInt32() ];

        console.log(sysSignature);
        if(sysSignature==null) {
            console.log( ' ['+this.locatePC(pContext)+']   \x1b[35;01m' + CC.OP + ' ('+sysNR+')\x1b[0m =<unknow>');
            return;
        }

        pContext.dxcRET = sysSignature[SyscallInfo.RET];

        let s:string = "", p:string= "";
        pContext.dxcOpts = [];
        sysSignature[SyscallInfo.ARGS].map((vVal:SyscallParamSignature,vOff:number) => {
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

    /**
     * To setup "trace" hook is the current instruction is an interruption or follow immediately one.
     *
     * This function is called by Stalker's event listener for each instruction
     *
     * @param {StalkerX86Iterator | StalkerArm64Iterator  | StalkerArmIterator| StalkerThumbIterator} pStalkerInterator The stalker iterator
     * @param {any} pInstruction The current instruction
     * @param {any} pExtra Some extra options
     * @method
     */
    trace( pStalkerInterator:StalkerX86Iterator
        | StalkerArm64Iterator
        | StalkerArmIterator
        | StalkerThumbIterator, pInstruction:any, pExtra:any):number{

        let mode = 'N';
        let addr = null;
        let insn =  null;
        const self = this;

        let keep = 1;
        if(pExtra.onLeave == 2){

            pStalkerInterator.putCallout(function(context:PortableCpuContext) {


                const richCtx = context as RichArmCpuContext;
                const n = richCtx[CC.NR].toInt32();

                if(richCtx.dxc==null) richCtx.dxc = {FD:{}};
                //if(isExcludedFn!=null && isExcludedFn(n)) return;
                if(self.scope.syscalls!=null && self.scope.syscalls.isExcluded!=null && self.scope.syscalls.isExcluded(n)) return;

                self.traceSyscallRet(richCtx);

                const hook = self.svc_hk[n];
                if(hook == null) return ;

                if(hook.onLeave != null){
                    (hook.onLeave)(richCtx);
                }
            });

            pExtra.onLeave = null;
        }


        // debug
       //console.log("["+pInstruction.address+" : "+pInstruction.address.sub(pExtra.mod.__mod.base)+"] > "+Instruction.parse(pInstruction.address));

        // instrumentation time
        /*try{
            mode = 'N';
            addr = parseInt(pInstruction.address,16);
            insn = Instruction.parse(pInstruction.address)
        }catch(e){
            mode = 'T';
            addr = addr+1;
            insn = Instruction.parse(ptr(addr));
        }

        console.log("[0x"+addr.toString(16)+"]["+mode+"] > "+insn);


        if(insn!=null){
            if(insn.toString().match(/swi/ig)){
                console.log("------------- [0x"+addr+"] T > "+insn);
            }
            insn = null;
        }*/


        /*
        if(self.catchOP!=null && self.catchOP.indexOf(pInstruction.mnemonic)>-1){
            console.log("PRE-CATCH > "+pInstruction.mnemonic);

            pStalkerInterator.putCallout(function(context) {
                console.log("CATCH ["+context.pc+"]> "+pInstruction.parse(context.pc));
            });
        }*/

        if(pInstruction.mnemonic == null){
            console.log("POTENTIAL BREAKPOINT> "+pInstruction.address);
        }


        if (pInstruction.mnemonic === CC.OP) {
            console.log("SWI>");

            pExtra.onLeave =  1;
            pStalkerInterator.putCallout(function(context) {

                const richCtx = context as RichArmCpuContext;
                const n = richCtx[CC.NR].toInt32();

                //if(isExcludedFn!=null && isExcludedFn(n)) return;
                if(self.scope.syscalls!=null && self.scope.syscalls.isExcluded!=null && self.scope.syscalls.isExcluded(n)) return;

                if(richCtx.dxc==null) richCtx.dxc = {FD:{}};
                const hook = self.svc_hk[n];


                if(hook != null && hook.onEnter != null) (hook.onEnter)(richCtx);

                self.traceSyscall(richCtx, hook);

            });
        }

        return keep;
    }



    printStats(){
        super.printStats(SWI);
    }
}