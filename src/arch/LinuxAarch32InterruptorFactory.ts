/**

 @author Georges-Bastien Michel <georges@reversense.com>
 @copyright Reversense SAS

 */
import {InterruptorGenericException} from "../common/InterruptorException";
import {T, L} from  "../common/Types";
import {X} from "../kernelapi/LinuxArm64Flags";
import {InterruptorAgent} from "../common/InterruptorAgent";
import {AbstractInterruptorFactory} from "../common/AbstractInterruptorFactory";
import {LinuxArm64InterruptorAgent, KAPI} from "./LinuxArm64InterruptorAgent";
import {Utils} from "../common/Utils";
import {LinuxAarch32InterruptorAgent} from "./LinuxAarch32InterruptorAgent";




export class LinuxAarch32InterruptorFactory extends AbstractInterruptorFactory {

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
    newAgentTracer(pConfig: any):InterruptorAgent {

        const agent = new LinuxAarch32InterruptorAgent(pConfig, LinuxAarch32InterruptorFactory._followThread);
        //agent.buildScope();
        return agent;
    }


    newStandaloneTracer(){
        return null ;
    }


}
