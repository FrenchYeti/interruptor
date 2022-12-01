import {CoverageAgent} from "../utilities/Coverage.js";
import {
    F,
    InterruptSignatureMap,
    L,
    SyscallHookMap,
    SyscallInfo
} from "./Types.js";
import {IStringIndex} from "../utilities/IStringIndex.js";
import {DebugUtils} from "./DebugUtils.js";
import {SVC} from "../syscalls/LinuxAarch64Syscalls.js";

let CTR = 0;


export interface DebugOptions {
    syscallLookup?:boolean;
    scope?:boolean;
    stalker?:boolean;
}

export interface NumericRange {
    start:number;
    stop:number;
    inc?:number;
}

export type ScopeFilter = number | string | ((...args: any[])=>boolean) | RegExp | NumericRange;

export interface Scope {
    _policy?:F;
    exclude?:ScopeFilter[];
    include?:ScopeFilter[];
    isExcluded?:((num:number)=>boolean)
}


export interface ScopeMap {
    modules?:Scope|null;
    syscalls?:Scope|null;
    ranges?:Scope|null;
    [customScope:string] :Scope|null;
}

interface InterruptorContext extends IStringIndex{
    agent: InterruptorAgent;
    tid: number;
    [name:string]: any;
}

/**
 * Interruptor lifecycle hooks
 * @interface
 */
interface InterruptorHooks {
    beforeStart?: ((ev:InterruptorContext)=>void),
    afterStart?: ((ev:InterruptorContext)=>void)
}

interface OuputHighlightOpts {
    syscalls?: any
}
/**
 * Configuration of the output printer
 * @interface
 */
interface OutputOpts {
    /**
     * Color associate to the current thread
     * @type number
     * @field
     */
    _tcolor: number;
    /**
     * The flavor define the template to use to print a log : dxc is the default flavor,
     * else "strace" ll produce same result than "strace"
     * @type {"dxc" | "strace"}
     * @field
     */
    flavor: "dxc" | "strace";
    tid: boolean;
    pid: boolean;
    module: boolean;
    dump_buff: boolean;
    hide: any;
    indent: string;
    highlight: OuputHighlightOpts;
    [name:string]:any;
}

export interface InterruptorAgentConfig {
    followThread?:boolean;
    followFork?:boolean;
    scope?: ScopeMap;
    onStart?: ((arg:any)=>void);
    svc?: SyscallHookMap;
    coverage?:any;
    hook?:InterruptorHooks;
    types?:any;
    debug?:DebugOptions;
    pid?:number;
    tid?:number;
    emulator?:boolean;
}



export class InterruptorAgent implements IStringIndex {


    _tids:number[] = [];

    static FLAVOR_DXC = "dxc";
    static FLAVOR_STRACE= "strace";

    uid = 0;

    ranges: any = new Map();
    modules: Module[] = [];


    /**
     * PID of process to stalk, when followFork is enabled or on attach
     * @type number
     * @field
     * @public
     */
    pid = -1;

    tid = -1;

    emulator:boolean;

    followFork = false;

    followThread = false;

    coverage?:CoverageAgent;

    // exclude: any = null;

    // include: any = null;

    interrupts: InterruptSignatureMap;

    scope:ScopeMap;

    debug:DebugOptions = {
        scope: false,
        syscallLookup: false,
        stalker: false
    };


    types:any = {};

    /**
     * To use with startOnLoad()
     * A callback function executed when the modules specified in "startOnLoad" are loaded
     * @type Function
     * @field
     * @public
     */
    onStart:any = ()=>{ /* empty */ };

    hook:InterruptorHooks = {
        beforeStart: null,
        afterStart: null
    };

    output:OutputOpts = {
        _tcolor: 0,
        flavor: "dxc",
        tid: true,
        pid: false,
        module: true,
        dump_buff: true,
        hide: null,
        indent:"",
        highlight: {
            syscalls: []
        }
    }

    _do_ft:any = null;

    /**
     *
     * @param {any} pConfig Options
     * @constructor
     */
    constructor( pOptions:InterruptorAgentConfig, pDoFollowThread:any = null, pInterrupts:InterruptSignatureMap = null) {
        this.uid = CTR++;
        this.emulator = false;
        this._do_ft = pDoFollowThread;
        if(pInterrupts != null){
            this.interrupts = pInterrupts;
        }else{
            this.interrupts = {
                syscalls: null
            }
        }

        this.scope = pOptions.scope;
        this.parseOptions(pOptions);
        //this.scope = this.scope;
    }

    /**
     * To parse object containing options
     *
     * @param {any} pConfig Options
     * @method
     * @public
     */
    parseOptions(pConfig:any):void {

        for(const k in pConfig){
            switch(k){
                case 'types':
                    this.types = pConfig.types;
                    break;
                case 'emulator':
                    this.emulator = pConfig.emulator;
                    break;
                case 'pid':
                    this.pid = pConfig.pid;
                    break;
                case 'tid':
                    this.tid = pConfig.tid;
                    break;
                case 'coverage':
                    this.coverage = CoverageAgent.from(pConfig.coverage, this);
                    break;
                case 'followFork':
                    this.followFork = (typeof pConfig.followFork !== "boolean" ? false : pConfig.followFork);
                    break;
                case 'followThread':
                    this.followThread = (typeof pConfig.followThread !== "boolean" ? false : pConfig.followThread);
                    if(!this.followThread){
                        this._do_ft = null;
                    }
                    break;
                case 'output':
                    for(const i in pConfig.output) this.output[i] = pConfig.output[i];
                    break;
                case 'hook':
                    this.hook = pConfig.hook;
                    break;
                case 'debug':
                    this.debug = pConfig.debug;
                    break;
                case 'scope':
                    this.scope = pConfig.scope; //this._prepareScope(pConfig.scope);
                    break;
                case 'onStart':
                    this.onStart = pConfig.onStart;
                    break;
            }
        }
    }

    /**
     * The aim of this method is to ttr
     * @param pSyscall
     */
    public prepareScope():void{
        // scan modules
        this._filterModuleScope();

        // scan syscalls
        this._filterSyscallScope();
    }

    /**
     *
     * @param pType
     * @param pOpts
     * @protected
     */
    protected _setupDelegateFilters(pType:string, pOpts:any):void {
        // nothing here
    }



    /**
     * To generate a filtered list of syscalls
     * @param {string[]} pSyscalls An array of syscall number
     * @method
     */
    getModuleList( pFilters:ScopeFilter[],  pSrcList:Module[] = [],  pList:string[] = []):string[] {

        if(pFilters == null){
            return [];
        }

        const modules:Module[] = (pSrcList.length==0) ? Process.enumerateModules() : pSrcList;
        const list:string[] = pList;

        pFilters.map((vFilter:ScopeFilter)=>{
            switch(typeof vFilter){
                case "string":
                    modules.map( x => { if(x.name==vFilter) list.push(x.name); });
                    break;
                case "function":
                    modules.map( x => { if((vFilter)(...[x])) list.push(x.name); });
                    break;
                case "object":
                    if(Array.isArray(vFilter)){
                        vFilter.map( sVal => {
                            list.concat(this.getModuleList(sVal, modules, list));
                        })
                    }else if(vFilter instanceof RegExp){
                        modules.map( x => { if(vFilter.exec(x.name)!=null) list.push(x.name); });
                    } // todo : add selection by range start -> end / size
                    break;
            }
        });


        return list;
    }


    /**
     * To generate a filtered list of syscalls
     * @param {string[]} pSyscalls An array of syscall number
     * @method
     */
    getSyscallList( pSyscalls:ScopeFilter ):number[] {

        const list:number[] = [];

        if(this.interrupts==null || this.interrupts.syscalls==null) return list;

        switch(typeof pSyscalls){
            case "string":
                this.interrupts.syscalls.map(x => { if(x[1]==pSyscalls) list.push(x[SyscallInfo.NUM]); });
                break;
            case "function":
                this.interrupts.syscalls.map( x => { if((pSyscalls)(...[x])) list.push(x[SyscallInfo.NUM]); });
                break;
            case "object":
                if(Array.isArray(pSyscalls)){
                    pSyscalls.map( sVal => {
                        switch(typeof sVal){
                            case "string":
                                this.interrupts.syscalls.map( x => { if(x[SyscallInfo.NAME]==sVal) list.push(x[SyscallInfo.NUM]); });
                                break;
                            case "number":
                                this.interrupts.syscalls.map( x => { if(x[SyscallInfo.NUM]==sVal) list.push(x[SyscallInfo.NUM]); });
                                break;
                            case "object":
                                this.interrupts.syscalls.map( x => {

                                    if(sVal.exec(x[SyscallInfo.NAME])!=null){
                                        const m = x[SyscallInfo.NUM]
                                        list.push(m);
                                        //console.log(sVal,x[SVC_NAME],m);
                                    }
                                });
                                break;
                        }
                    })
                }else if (pSyscalls instanceof RegExp){
                    this.interrupts.syscalls.map( x => { if(pSyscalls.exec(x[1])!=null) list.push(x[0]); });
                }else{
                    this.interrupts.syscalls.map(x => { list.push(x[SyscallInfo.NUM]); });
                }
                break;
            default:
                this.interrupts.syscalls.map(x => { list.push(x[SyscallInfo.NUM]); });
                break;
        }

        return list;
    }

    /**
     *
     * @private
     */
    private _filterSyscallScope():void {

        let syscalls:number[] = [];

        if(this.scope.syscalls!=null){

            const scope:Scope = this.scope.syscalls;

            if(scope.exclude){
                // if there is an exclusion list, then the default behavior is to include any
                scope._policy = F.INCLUDE_ANY;

                if(scope.exclude != null){
                    scope.exclude.map((vFilter)=>{
                        syscalls = syscalls.concat(this.getSyscallList(vFilter));
                    });
                }

                scope.exclude = syscalls;
                scope.isExcluded = (x:number)=>{ return (syscalls.indexOf(x)>-1) };
            }else{
                // if there is an inclusion list, then the default behavior is to exclude any
                scope._policy = F.EXCLUDE_ANY;
                if(scope.include != null){
                    scope.include.map((vFilter)=>{
                        syscalls = syscalls.concat(this.getSyscallList(vFilter));
                    });
                }

                scope.include = syscalls;
                scope.isExcluded = (x:number)=>{ return !(syscalls.indexOf(x)>-1) };
            }

        }else{
            this.scope.syscalls = {
                exclude:[],
                _policy: F.INCLUDE_ANY,
                isExcluded: (x:number)=>{ return false; }
            };
        }
    }

    /**
     * To compute the list of stalked module from include/exclude options
     *
     * @method
     */
    private _filterModuleScope():void {

        let modules:string[];
        let map:ModuleMap = new ModuleMap();

        if(this.scope.modules!=null){

            const scope:Scope = this.scope.modules;

            if(scope.exclude){
                // if there is an exclusion list, then the default behavior is to include any
                scope._policy = F.INCLUDE_ANY;
                if(scope.exclude == null) scope.exclude = [];
            }else{
                // if there is an inclusion list, then the default behavior is to exclude any
                scope._policy = F.EXCLUDE_ANY;
                if(scope.include == null) scope.include = [];
            }

            //list = this._scope.modules != null ? this.getModuleList(this._scope.modules) : this.getModuleList(null);

            if(scope._policy == F.EXCLUDE_ANY){
                // authorized modules
                scope.include = modules = this.getModuleList(scope.include==null? [] : scope.include);
                map = new ModuleMap((m) => {
                    if(modules.indexOf(m.name)==-1){
                        if(this.debug.scope) console.log("[DEBUG] Excluded : "+JSON.stringify(m));
                        Stalker.exclude(m);
                        return false;
                    }
                    //console.log("Modules included : "+m.name);
                    return true;
                });
            }
            else if(scope._policy == F.INCLUDE_ANY){
                // excluded modules
                scope.exclude = modules = this.getModuleList(scope.exclude==null? [] : scope.exclude);
                map = new ModuleMap((m) => {
                    if(modules.indexOf(m.name)>-1){
                        if(this.debug.scope)  console.log("[DEBUG] Excluded : "+JSON.stringify(m));
                        Stalker.exclude(m);
                        return false;
                    }
                    //console.log("Modules included : "+m.name);
                    return true;
                });
            }
            else{
                // filter mode
                /*
                if(this._scope.modules.i == null){
                    modules = Process.enumerateModules().map( x => x.name);
                }else{
                    modules = this.getModuleList (this._scope.modules.i);
                }

                //if(this._scope.modules == null)
                const exc = this.getModuleList(this._scope.modules.e);

                // filter authorized list with excluded modules
                modules = modules.filter(x => { return exc.indexOf(x)==-1 });

                map = new ModuleMap((m) => {
                    // check if module is authorized
                    if(modules.indexOf(m.name)==-1){
                        Stalker.exclude(m);
                        return false;
                    }
                    // console.log("Modules (filter): "+m.name);
                    return true;
                });*/
            }
        }else{
            if(this.scope.modules==null) this.scope.modules = {
                isExcluded: ()=>{return false}
            };
            this.scope.modules._policy = F.INCLUDE_ANY;
        }

        this.modules = map.values();
        for (const module of this.modules) {
            const ranges = module.enumerateRanges("--x");
            this.ranges.set(module.base, ranges);
        }
    }


    /**
     * To check if coverage is enabled
     *
     * @return {boolean} TRUE is coverage is enabled, else FALSE
     * @methpd
     */
    isTrackCoverage():boolean {
        return  (this.coverage != null && this.coverage.enabled);
    }

    /**
     * To process coverage events
     *
     * @param pStalkerEvents
     */
    processBbsCoverage( pStalkerEvents: StalkerEventFull[] | StalkerEventBare[]){

        pStalkerEvents.forEach((e) => {
            if(this.coverage!=null) this.coverage.processStalkerEvent(e);
        });
    }


    trace( pStalkerInterator:any, pInstruction:any, pExtra:any):number {
        return 1;
    }


    /**
     * To start tracing when a specifc module is loaded, and an optional condition verified
     *
     * Must be overridden by architecture specific interruptors
     *
     * @param pModuleRegExp
     * @param pOptions
     */
    startOnLoad( pModuleRegExp:RegExp, pOptions:any = null):any {
        return new Error("Dynamic loading is not supported");
    }

    /**
     * To start to trace
     *
     */
    start( pTID = -1){

        if(this.hook.beforeStart != null){
            this.hook.beforeStart.apply(null, [{ agent:this, tid:pTID }]);
        }

        //this._buildScope();
        //this._buildScope();

        if(this.debug.scope){
            DebugUtils.printModuleScopes(this);
            DebugUtils.printSyscallScopes(this);
        }


        let tid = (pTID > -1) ? pTID : null;
        if(tid === null){
            if(this.tid > -1){
                tid = this.tid;
            }else{
                tid = Process.getCurrentThreadId();
            }
        }

        if(this._tids.indexOf(tid)>-1){
            console.warn(this.output.indent+"[INTERRUPTOR][STARTING] Thread already tracked");
            return;
        }else{
            console.warn(this.output.indent+"[INTERRUPTOR][STARTING] Tracing thread "+tid+" ["+this._tids.join(",")+"]");
            this._tids.push(tid);
        }


        //const self = this;
        const pExtra:any = {};

        console.log(this.output.indent+"[STARTING TRACE] UID="+this.uid+" Thread "+tid);

        // to exclude configured ranges/modules from Stalker
        // this._filterModuleScope();



        // Configure staker
        const opts:StalkerOptions = {
            events: {
                call: true
            },
            transform: (iterator: StalkerX86Iterator
                | StalkerArm64Iterator
                | StalkerArmIterator
                | StalkerThumbIterator )=>{

                let instruction; // Arm64Instruction | X86Instruction | null;

                let next = 0;

                const threadExtra:any = pExtra;
                threadExtra.hookAfter =  null;
                threadExtra.onLeave =  null;

                while ((instruction = iterator.next()) !== null) {
                    next = 1;

                    next = this.trace( iterator, instruction, threadExtra );
                    //next = self.trace( iterator, instruction, threadExtra );

                    if(next==-1){
                        continue;
                    }
                    if(next>0){
                        iterator.keep();
                    }
                }
            }
        }

        // update stalker option if coverage tracking is enabled
        if(this.isTrackCoverage()){

            console.log("TRACK COVERAGE");
            if(opts.events==null){
                opts.events = {};
            }
            opts.events.compile = true;
            opts.onReceive = (pEvents: ArrayBuffer)=>{


                //console.log(pEvents);
                this.processBbsCoverage(
                    Stalker.parse( pEvents, {
                        annotate: true,
                        stringify: false,
                    })
                );
            };

            if(this.coverage != null) this.coverage.initOutput();

        }


        // Stalker.trustThreshold = 1;
        Stalker.follow(tid, opts);

        // prevent interceptor issue
        if(this._do_ft !== null){
            this._do_ft(this);
        }


        if(this.hook.afterStart != null){
            this.hook.afterStart.apply(null,  [{ agent:this, tid:tid, opts:opts }] );
        }
    }

    /**
     * To print statistics about implementation
     *
     * @param pSyscallList
     */
    printStats( pSyscallList:any[] = []){
        const stats = { handlers:0, err:0, atot:0, untyped:0, todo:0, struct:0 };
        const types = {};

        // list partially implemented syscall
        let msgPart = "\t - ";

        stats.handlers = pSyscallList.length;
        pSyscallList.map((sc)=>{
            let impl=true;
            let arg:any = null;

            if(sc[4]!=null && sc[4].e!=null && sc[4].e.length>0) stats.err++;
            for(let i=0; i<sc[3].length; i++){
                arg = sc[3][i];
                // detect args not typed
                if(typeof (arg)==="string"){ impl=false; break;}
                // detect structure not supported
                if(arg.l != null && arg.l==L.DSTRUCT){
                    if((types as any)[arg.f]==null)
                        (types as any)[arg.f]=1;
                    else
                        (types as any)[arg.f]++;
                }
            }
            stats.untyped += (!impl ? 1: 0);

            if(!impl){
                stats.untyped++;
                msgPart += ` ${sc[1]}, `;
            }
        });

        // list not implemented structures
        let msgImpl = "\t - ";
        const notImpl=[];
        for(const s in types){
            if(this.types[s]==null){
                notImpl.push(s);
                msgImpl += ` ${s} (${(types as any)[s]}), `;
            }
        }

        console.log(`System calls : ${pSyscallList.length}
Support primitive args parsing : ${pSyscallList.length - stats.untyped}/${pSyscallList.length} \n ${msgPart} \n\n 
Support struct args implemented : ${notImpl.length}/${Object.keys(types).length} \n ${msgImpl} \n\n
Support err code : ${stats.err}/${pSyscallList.length}
        `)
    }

}