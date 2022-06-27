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


function deepCopy(pSrcObject:any): any {
    const destObj = {};
    for(let i in pSrcObject){
        if(typeof pSrcObject[i] == 'object' && pSrcObject[i] !== null){
            destObj[i] = deepCopy(pSrcObject[i]);
        }else{
            destObj[i] = pSrcObject[i];
        }
    }
    return destObj;
}

export class LinuxArm64InterruptorFactory extends AbstractInterruptorFactory {

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
        LinuxArm64InterruptorFactory.HOOKED_PTHREAD_ROUTINE = {};
        Interceptor.attach( Module.findExportByName("libc.so","pthread_create"), {
            onEnter: function(args){
                let routine = args[2];

                if(routine != null && !LinuxArm64InterruptorFactory.HOOKED_PTHREAD_ROUTINE.hasOwnProperty(routine)){
                    LinuxArm64InterruptorFactory.HOOKED_PTHREAD_ROUTINE[routine+""]=true;
                    console.log("["+Process.findModuleByAddress(this.context.pc).name+"] Hooking routine : "+routine+" "
                        +JSON.stringify(LinuxArm64InterruptorFactory.HOOKED_PTHREAD_ROUTINE));

                    Interceptor.attach( routine, {
                        onEnter: function(a){
                            const m = Process.findModuleByAddress(this.context.pc);
                            console.log("------- [TID="+this.threadId+"]["+m.name+"]["+routine+"] Thread routine start -------");

                            //console.log(JSON.stringify(self),self._pickThreadColor);
                            const cfg = deepCopy(pConfig);
                            cfg.output._tcolor = AbstractInterruptorFactory._pickThreadColor();
                            const b = new LinuxArm64InterruptorAgent(cfg, this._followThread);
                            LinuxArm64InterruptorFactory.AGENTS.push(b);
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

        const agent = new LinuxArm64InterruptorAgent(pConfig, LinuxArm64InterruptorFactory._followThread);
        //agent.buildScope();
        return agent;
    }


    newStandaloneTracer(){
        return null ;
    }


}
