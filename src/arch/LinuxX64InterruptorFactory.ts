/**

 @author Georges-Bastien Michel <georges@reversense.com>
 @copyright Reversense SAS

 */
import {InterruptorGenericException} from "../common/InterruptorException";
import {T, L} from  "../common/Types.js";
import {X} from "../kernelapi/LinuxX64Flags.js";
import {InterruptorAgent} from "../common/InterruptorAgent.js";
import {AbstractInterruptorFactory} from "../common/AbstractInterruptorFactory.js";
import {Utils} from "../common/Utils.js";
import {LinuxX64InterruptorAgent, KAPI} from "./LinuxX64InterruptorAgent.js";




export class LinuxX64InterruptorFactory extends AbstractInterruptorFactory {

    KAPI:any = KAPI;
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
        LinuxX64InterruptorFactory.HOOKED_PTHREAD_ROUTINE = {};
        Interceptor.attach( Module.findExportByName("libc.so","pthread_create"), {
            onEnter: function(args){
                let routine = args[2];

                if(routine != null && !LinuxX64InterruptorFactory.HOOKED_PTHREAD_ROUTINE.hasOwnProperty(routine)){
                    LinuxX64InterruptorFactory.HOOKED_PTHREAD_ROUTINE[routine+""]=true;
                    console.log("["+Process.findModuleByAddress(this.context.pc).name+"] Hooking routine : "+routine+" "
                        +JSON.stringify(LinuxX64InterruptorFactory.HOOKED_PTHREAD_ROUTINE));

                    Interceptor.attach( routine, {
                        onEnter: function(a){
                            const m = Process.findModuleByAddress(this.context.pc);
                            console.log("------- [TID="+this.threadId+"]["+m.name+"]["+routine+"] Thread routine start -------");

                            //console.log(JSON.stringify(self),self._pickThreadColor);
                            const cfg = Utils.deepCopy(pConfig);
                            cfg.output._tcolor = AbstractInterruptorFactory._pickThreadColor();
                            const b = new LinuxX64InterruptorAgent(cfg, this._followThread);
                            LinuxX64InterruptorFactory.AGENTS.push(b);
                            b.start(this.threadId);
                        },
                        onLeave: function(a){
                            console.log("------- [TID="+this.threadId+"]["+routine+"] Thread routine ended -------");

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
    newAgentTracer(pConfig: any):InterruptorAgent {

        const agent = new LinuxX64InterruptorAgent(pConfig, LinuxX64InterruptorFactory._followThread);
        //agent.buildScope();
        return agent;
    }


    newStandaloneTracer(){
        return null ;
    }


}
