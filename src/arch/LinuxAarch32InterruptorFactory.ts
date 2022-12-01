/**

 @author Georges-Bastien Michel <georges@reversense.com>
 @copyright Reversense SAS

 */
import {T, L} from  "../common/Types.js";
import {X} from "../kernelapi/LinuxArm64Flags.js";
import {InterruptorAgent} from "../common/InterruptorAgent.js";
import {AbstractInterruptorFactory} from "../common/AbstractInterruptorFactory.js";
import {LinuxArm64InterruptorAgent, KAPI} from "./LinuxArm64InterruptorAgent.js";
import {Utils} from "../common/Utils.js";
import {LinuxAarch32InterruptorAgent, LinuxAarch32InterruptorAgentConfig} from "./LinuxAarch32InterruptorAgent.js";
import {KernelAPI} from "../kernelapi/Types";




export class LinuxAarch32InterruptorFactory extends AbstractInterruptorFactory {

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
        LinuxAarch32InterruptorFactory.HOOKED_PTHREAD_ROUTINE = {};
        Interceptor.attach( Module.findExportByName("libc.so","pthread_create"), {
            onEnter: function(args){
                let routine = args[2];

                if(routine != null && !LinuxAarch32InterruptorFactory.HOOKED_PTHREAD_ROUTINE.hasOwnProperty(routine)){
                    LinuxAarch32InterruptorFactory.HOOKED_PTHREAD_ROUTINE[routine+""]=true;
                    console.log("["+Process.findModuleByAddress(this.context.pc).name+"] Hooking routine : "+routine+" "
                        +JSON.stringify(LinuxAarch32InterruptorFactory.HOOKED_PTHREAD_ROUTINE));

                    Interceptor.attach( routine, {
                        onEnter: function(a){
                            const m = Process.findModuleByAddress(this.context.pc);
                            console.log("------- [TID="+this.threadId+"]["+m.name+"]["+routine+"] Thread routine start -------");

                            //console.log(JSON.stringify(self),self._pickThreadColor);
                            const cfg = Utils.deepCopy(pConfig);
                            cfg.output._tcolor = AbstractInterruptorFactory._pickThreadColor();
                            const b = new LinuxAarch32InterruptorAgent(cfg, this._followThread);
                            LinuxAarch32InterruptorFactory.AGENTS.push(b);
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
    newAgentTracer(pConfig: LinuxAarch32InterruptorAgentConfig):InterruptorAgent {

        const agent = new LinuxAarch32InterruptorAgent(pConfig, LinuxAarch32InterruptorFactory._followThread);
        //agent.buildScope();
        return agent;
    }


    newStandaloneTracer():InterruptorAgent{
        return null ;
    }


}
