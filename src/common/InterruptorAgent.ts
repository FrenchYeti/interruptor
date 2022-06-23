import {CoverageAgent} from "../utilities/Coverage";

let CTR = 0;


export enum F {
    EXCLUDE_ANY,
    INCLUDE_ANY,
    FILTER
}

export class InterruptorAgent {


    _tids:number[] = [];

    static FLAVOR_DXC = "dxc";
    static FLAVOR_STRACE= "strace";

    uid:number = 0;

    ranges: any = new Map();
    modules: any[] = [];


    /**
     * PID of process to stalk, when followFork is enabled or on attach
     * @type number
     * @field
     * @public
     */
    pid: number = -1;

    tid: number = -1;

    emulator:boolean;

    followFork:boolean = false;

    followThread:boolean = false;

    coverage:CoverageAgent = null;

    exclude: any = null;

    include: any = null;

    moduleFilter: any = null;

    debug:boolean = false;

    types:any = null;

    /**
     * Filter type : include, equal, exclude
     */
    _policy:any = {};

    _scope:any = {};

    /**
     * To use with startOnLoad()
     * A callback function executed when the modules specified in "startOnLoad" are loaded
     * @type Function
     * @field
     * @public
     */
    onStart:any = ()=>{};


    output:any = {
        _tcolor: 0,
        flavor: "dxc",
        tid: true,
        pid: false,
        module: true,
        dump_buff: true,
        hide: null,
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
    constructor( pOptions:any, pDoFollowThread:any = null) {
        this.uid = CTR++;
        this.emulator = false;
        this._do_ft = pDoFollowThread;
        this.parseOptions(pOptions);
    }

    /**
     * To parse object containing options
     *
     * @param {any} pConfig Options
     * @method
     * @public
     */
    parseOptions(pConfig:any):void {

        for(let k in pConfig){
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
                case 'include':
                case 'exclude':
                    this._setupFilters(k, pConfig[k]);
                    break;
                case 'moduleFilter':
                    this.moduleFilter = pConfig.moduleFilter;
                    break;
                case 'onStart':
                    this.onStart = pConfig.onStart;
                    break;
            }
        }
    }

    /**
     *
     * @param pType
     * @param pOpts
     * @protected
     */
    protected _setupDelegateFilters(pType:string, pOpts:any):void {

    }


    /**
     * The aime of this function is to compute final scope by merging
     * exclude / include options
     *
     * @param pType
     * @param pOpts
     * @protected
     */
    protected _buildScope():any {
        this._scope = {
            modules: null,
            syscalls: null
        };

        if(this.include != null){
            for(let i in this.include){
                this._policy[i] = F.EXCLUDE_ANY;
                this._scope[i] = this.include[i];
            }
        }else{
            for(let i in this._scope){
                this._policy[i] = F.INCLUDE_ANY;
            }
        }

        if(this.exclude != null){
            for(let i in this.exclude){
                // true only if "include" is defined
                if(this._scope.hasOwnProperty(i) && this._scope[i] != null){
                    if(this._policy[i] == F.EXCLUDE_ANY){
                        this._policy[i] = F.FILTER;
                        this._scope[i] = { i: this._scope[i], e:this.exclude[i] }
                    }else{
                        this._policy[i] = F.INCLUDE_ANY;
                        this._scope[i] = this.exclude[i];
                    }
                    //this._scope[i] = this._scope[i].filter( v => this.exclude[i].indexOf(v)==-1 );
                }else{
                    // else, filtering only
                    this._policy[i] = F.INCLUDE_ANY; // keep only element not in the list
                    this._scope[i] = this.exclude[i];
                }
            }
        }

        this._updateScope(this._scope, this._policy);
    }

    protected _updateScope(pScope:any, pPolicy:any):void {

    }

    /**
     *
     * @param pType
     * @param pOpts
     * @private
     */
    private _setupFilters(pType:string, pOpts:any):void {

        if(this[pType]==null) this[pType] = {};

        const filt = this[pType];
        for(const t in pOpts){
            for(const ppt in pOpts){
                switch(ppt){
                    case "modules":
                        filt.modules = pOpts.modules;
                        break;
                    case "syscalls":
                        filt.syscalls = pOpts.syscalls;
                        break;
                }
            }
        }

        this._setupDelegateFilters(pType, pOpts);
    }


    /**
     * To generate a filtered list of syscalls
     * @param {string[]} pSyscalls An array of syscall number
     * @method
     */
    getModuleList( pFilter:any,  pSrcList:Module[] = null,  pList:any = []):any {

        if(pFilter == null){
            return [];
        }

        const mods:Module[] = pSrcList==null ? Process.enumerateModules() : pSrcList;
        const list = pList;
        switch(typeof pFilter){
            case "string":
                mods.map( x => { if(x.name==pFilter) list.push(x.name); });
                break;
            case "function":
                mods.map( x => { if(pFilter.apply(null, x)) list.push(x.name); });
                break;
            case "object":
                if(Array.isArray(pFilter)){
                    pFilter.map( sVal => {
                        list.concat(this.getModuleList(sVal, mods, list));
                    })
                }else if(pFilter instanceof RegExp){
                    mods.map( x => { if(pFilter.exec(x.name)!=null) list.push(x.name); });
                } // todo : add selection by range start -> end / size
                break;
        }

        return list;
    }

    /**
     * To compute the list of stalked module from include/exclude options
     *
     * @method
     */
    private _filterModuleScope():void {

        let modules:string[];
        let map:ModuleMap;

        if(this._scope.hasOwnProperty("modules") && this._scope.modules!=null){

            if(!this._scope.hasOwnProperty("modules")){
                this._policy.modules = F.INCLUDE_ANY;
            }

            //list = this._scope.modules != null ? this.getModuleList(this._scope.modules) : this.getModuleList(null);

            if(this._policy.modules == F.EXCLUDE_ANY){
                // authorized modules
                modules = this.getModuleList(this._scope.modules);
                map = new ModuleMap((m) => {
                    if(modules.indexOf(m.name)==-1){
                        Stalker.exclude(m);
                        return false;
                    }
                    //console.log("Modules (exclude any): "+m.name);
                    return true;
                });
            }
            else if(this._policy.modules == F.INCLUDE_ANY){
                // excluded modules
                modules = this.getModuleList(this._scope.modules);
                map = new ModuleMap((m) => {
                    if(modules.indexOf(m.name)>=-1){
                        Stalker.exclude(m);
                        return false;
                    }
                    //console.log("Modules (include any): "+m.name);
                    return true;
                });
            }
            else{
                if(this._scope.modules == null || this._scope.modules.i == null){
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
                });
            }
        }else{
            this._policy.modules = F.INCLUDE_ANY;
            map = new ModuleMap();
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
    processBbsCoverage( pStalkerEvents:any){
        pStalkerEvents.forEach((e) => {
            this.coverage.processStalkerEvent(e);
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
    start( pTID:number = -1){


        this._buildScope();

        if(this.debug){
            if(this._scope.modules.length > 0){
                console.log(this._scope);
            }
            if(this._scope.syscalls.length > 0){
                console.log(this._scope);
            }
        }


        // @ts-ignore
        let tid = pTID > -1 ? pTID : null;
        if(tid === null){
            if(this.tid > -1){
                tid = this.tid;
            }else{
                tid = Process.getCurrentThreadId();
            }
        }

        if(this._tids.indexOf(tid)>-1){
            console.warn("[INTERRUPTOR][STARTING] Thread already tracked");
            return;
        }else{
            console.warn("[INTERRUPTOR][STARTING] Tracing thread "+tid+" ["+this._tids.join(",")+"]");
            this._tids.push(tid);
        }


        const self = this;
        let pExtra:any = {};

        console.log("[STARTING TRACE] UID="+this.uid+" Thread "+tid);

        // to exclude configured ranges
        this._filterModuleScope();



        // Configure staker
        const opts:any = {
            events: {
                call: true
            },
            transform: function(iterator){
                let instruction; // Arm64Instruction | X86Instruction | null;

                let next:number = 0;

                let threadExtra:any = pExtra;
                threadExtra.hookAfter =  null;
                threadExtra.onLeave =  null;

                while ((instruction = iterator.next()) !== null) {
                    next = 1;

                    //console.log(instruction);
                    next = self.trace( iterator, instruction, threadExtra );

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
            opts.events.compile = true;
            opts.onReceive = (pEvents)=>{
                //console.log(pEvents);
                this.processBbsCoverage(
                    Stalker.parse(pEvents, {
                        annotate: true,
                        stringify: false,
                    })
                );
            };

            this.coverage.initOutput();

        }

        // @ts-ignore
        // Stalker.trustThreshold = 1;
        Stalker.follow(tid, opts);

        // prevent interceptor issue
        if(this._do_ft !== null){
            this._do_ft(this);
        }
    }

}