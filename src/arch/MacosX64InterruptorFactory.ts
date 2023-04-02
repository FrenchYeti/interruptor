/**

 @author Georges-Bastien Michel <georges@reversense.com>
 @copyright Reversense SAS

 */
import {T, L} from  "../common/Types.js";
import {X} from "../kernelapi/MacosArm64Flags.js";
import {InterruptorAgent} from "../common/InterruptorAgent.js";
import {AbstractInterruptorFactory} from "../common/AbstractInterruptorFactory.js";
import {MacosX64InterruptorAgent, KAPI, MacosX64InterruptorAgentConfig} from "./MacosX64InterruptorAgent.js";
import {SVC} from "../syscalls/MacosAarch64Syscalls.js";
import {KernelAPI} from "../kernelapi/Types.js";



function deepCopy(pSrcObject:any): any {
    const src:any = pSrcObject;
    const destObj:any = {};
    for(const i in src){
        if(typeof src[i] == 'object' && src[i] !== null){
            if(Array.isArray(src[i])){
                const arr:any[] = [];
                src[i].map((x:any) => {
                    if(typeof x == 'object' && x !== null){
                        arr.push(deepCopy(x));
                    }else{
                        arr.push(x);
                    }
                });
                destObj[i] = arr;
            }else{
                destObj[i] = deepCopy(src[i]);
            }
        }else{
            destObj[i] = src[i];
        }
    }
    return destObj;
}


export class MacosX64InterruptorFactory extends AbstractInterruptorFactory {

    KAPI:KernelAPI = KAPI;

    T:any = T;
    L:any = L;
    X:any = X;

    static HOOKED_PTHREAD_ROUTINE: any = {};
    static AGENTS: any[] = [];

    constructor( pOptions:any = null) {
        super(pOptions);
    }

    utils(){
        return {
            toScanPattern: AbstractInterruptorFactory.toScanPattern,
            toByteArray: AbstractInterruptorFactory.toByteArray,
            printBackTrace: AbstractInterruptorFactory.printBackTrace
        };
    }

    static _followThread(pConfig:any){

        console.error("Deploying pthread_create hook");
        MacosX64InterruptorFactory.HOOKED_PTHREAD_ROUTINE = {};

        let depth=0;
        const addr = Module.findExportByName("libc.so","pthread_create");
        if(addr == null) throw new Error("[ERROR] Thread cannot be followed : libc/pthread_create cannot be hooked");

        Interceptor.attach( addr, {
            onEnter: function(args){
                const routine = args[2];

                depth++;
                if(routine != null && !MacosX64InterruptorFactory.HOOKED_PTHREAD_ROUTINE.hasOwnProperty(routine)){
                    MacosX64InterruptorFactory.HOOKED_PTHREAD_ROUTINE[routine+""]=true;

                    const indent = "\t".repeat(depth);
                    const ptid = "[PTID="+Process.getCurrentThreadId()+"]";
                    //console.log(indent+"["+Process.findModuleByAddress(this.context.pc).name+"] Hooking routine : "+routine+" "
                    //    +JSON.stringify(LinuxArm64InterruptorFactory.HOOKED_PTHREAD_ROUTINE));

                    Interceptor.attach( routine, {
                        onEnter: function(a){

                            let m:any = {};

                            if(this.context.pc != null){
                                const x = Process.findModuleByAddress(this.context.pc);
                                if(x != null) m = x;
                            }

                            if(m.name.length==0){
                                m.name = 'MISSING_MODULE'
                            }


                            console.log("\n"+indent+"------- [TID="+this.threadId+"]["+m.name+"]["+routine+"] Thread routine start -------");

                            //AbstractInterruptorFactory.printBackTrace(this.context);
                            //console.log(JSON.stringify(self),self._pickThreadColor);
                            const cfg = deepCopy(pConfig);
                            cfg.output.indent = indent;
                            cfg.output._tcolor = AbstractInterruptorFactory._pickThreadColor();
                            const b = new MacosX64InterruptorAgent(cfg, this._followThread,{
                                syscalls: SVC
                            } );
                            MacosX64InterruptorFactory.AGENTS.push(b);
                            b.start(this.threadId);
                        },
                        onLeave: function(a){
                            console.log(indent+"------- [TID="+this.threadId+"]["+routine+"] Thread routine ended -------\n");

                        }
                    } )
                }
            }
        });
    }
    /**
     * To create a new Frida agent
     * @param pConfig
     */
    newAgentTracer(pConfig: MacosX64InterruptorAgentConfig):InterruptorAgent {

        const agent = new MacosX64InterruptorAgent(pConfig, MacosX64InterruptorFactory._followThread, {
            syscalls: SVC
        });

        agent.prepareScope();
        //agent.buildScope();
        return agent;
    }

/*
    newStandaloneTracer():any{
        return  ;
    }
*/

}
