//import {Stalker} from "frida"
import {InterruptorGenericException} from "./InterruptorException";
import {CoverageAgent} from "../utilities/Coverage";

let CTR = 0;

export class InterruptorAgent {

    static FLAVOR_DXC = "dxc";
    static FLAVOR_STRACE= "strace";

    uid:number = 0;

    ranges: any = new Map();
    modules: any[] = [];

    pid: number = -1;
    tid: number = -1;
    followFork:boolean = false;
    followThread:boolean = false;
    coverage:CoverageAgent = null;
    exclude: any = {
        modules: [],
        syscalls: []
    };
    moduleFilter: any = null;

    output:any = {
        flavor: "dxc",
        tid: true,
        pid: false,
        module: true,
        highlight: {
            syscalls: []
        }
    }

    constructor( pOptions:any) {
        this.uid = CTR++;
        this.parseOptions(pOptions);
    }

    parseOptions(pConfig:any):void {

        for(let k in pConfig){
            switch(k){
                case 'pid':
                    if(typeof pConfig.pid !== "number")
                        throw InterruptorGenericException.INVALID_PID();
                    this.pid = pConfig.pid;
                    break;
                case 'tid':
                    if(typeof pConfig.tid !== "number")
                        throw InterruptorGenericException.INVALID_TID();
                    this.tid = pConfig.tid;
                    break;
                case 'coverage':
                    this.coverage = CoverageAgent.from(pConfig.coverage, this);
                    break;
                case 'followFork':
                    this.followFork = (typeof pConfig.followFork !== "boolean" ? false : pConfig.followFork);
                    break;
                case 'followThread':
                    this.followThread = (typeof pConfig.followFork !== "boolean" ? false : pConfig.followFork);
                    break;
                case 'exclude':
                    for(k in pConfig.exclude){
                        this.exclude[k] = pConfig.exclude[k];
                    }
                    break;
                case 'output':
                    for(k in pConfig.output){
                        this.output[k] = pConfig.output[k];
                    }
                    break;
                case 'moduleFilter':
                    this.moduleFilter = pConfig.moduleFilter;
                    break;
            }
        }
    }


    /**
     * To check if coverage is enabled
     */
    isTrackCoverage():boolean {
        return  (this.coverage != null && this.coverage.enabled);
    }

    /**
     * to process coverage events
     * @param pStalkerEvents
     */
    processBbsCoverage( pStalkerEvents:any){
        pStalkerEvents.forEach((e) => {
            this.coverage.processStalkerEvent(e);
        });
    }


    /**
     * To exclude some range from stalker
     */
    filterModuleScope(){


        let map:ModuleMap;
        if(this.moduleFilter != null){
            map = new ModuleMap((m) => {
                if ((this.moduleFilter)(m)) {
                    console.warn("[INCLUDE] Module : "+m.name);
                    return true;
                }
                Stalker.exclude(m);
                return false;
            });
        }else{
            map = new ModuleMap((m) => {
                if(this.exclude.modules.indexOf(m.name)==-1){
                    console.warn("[INCLUDE] Module : " + m.name);
                    return true;
                }
                Stalker.exclude(m);
                return false;
            });
            /*
            this.exclude.modules.map( (r:any) => {
                if(typeof r === "string"){
                    // @ts-ignore
                    console.warn("[EXCLUDE] Module : "+r);
                    let m = Process.findModuleByName(r);
                    if(m != null){
                        Stalker.exclude( Process.findModuleByName(r));
                    }else{
                        console.error("[EXCLUDE] Error : module '"+r+"' not found. ");
                    }

                }else if(r.base != null && r.size !== null){
                    // @ts-ignore
                    console.warn("[EXCLUDE] Module : "+r.name);
                    Stalker.exclude( r);
                }
            })*/
        }


        this.modules = map.values();
        for (const module of this.modules) {
            const ranges = module.enumerateRanges("--x");
            this.ranges.set(module.base, ranges);
        }
    }

    trace( pStalkerInterator:any, pInstruction:any, pExtra:any):number {
        return 1;
    }

    /**
     * To start to trace
     *
     */
    start(){
        // @ts-ignore
        const tid = this.tid > -1 ? this.tid : Process.getCurrentThreadId()
        const self = this;
        let pExtra:any = {};

        console.log("[STARTING TRACE] UID="+this.uid+" Thread "+tid);

        // to exclude configured ranges
        this.filterModuleScope();



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
        Stalker.follow(tid, opts)
    }

}