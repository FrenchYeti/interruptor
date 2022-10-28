import {InterruptorAgent} from "./InterruptorAgent.js";
import {F} from "./Types.js";


export class DebugUtils {

    static getPolicyName(pPolicy:F):string{
        switch (pPolicy){
            case F.EXCLUDE_ANY:
                return "EXCLUDE_ANY";
                break;
            case F.INCLUDE_ANY:
                return "INCLUDE_ANY";
                break;
            case F.FILTER:
                return "FILTER";
                break;
        }

        return "OTHER";
    }
    static printModuleScopes( pAgent:InterruptorAgent):void {
        DebugUtils.printScope( pAgent, "modules");
    }

    static printSyscallScopes( pAgent:InterruptorAgent):void {
        DebugUtils.printScope( pAgent, "syscalls");
    }

    /**
     * To debug scopes
     *
     * @param pAgent
     * @param pScope
     */
    static printScope( pAgent:InterruptorAgent, pScope:string):void {
        if(pAgent.scope!=null && pScope!=null && pAgent.scope[pScope]!=null){

            const policy = (pAgent.scope[pScope]._policy!=null ? pAgent.scope[pScope]._policy : F.INCLUDE_ANY);
            let m:string;

            if(pAgent.scope[pScope] != null && policy!==F.FILTER){
                m = `[DEBUG][Scope=${pScope}][Policy=${DebugUtils.getPolicyName(policy)}] Scope `;
                if(policy==F.EXCLUDE_ANY) m += "except :"+JSON.stringify(pAgent.scope[pScope].include);
                if(policy==F.INCLUDE_ANY) m += "except :"+JSON.stringify(pAgent.scope[pScope].exclude);
                console.log(m);
            }else {
                console.log(`[DEBUG][Scope=${pScope}][Policy=${DebugUtils.getPolicyName(policy)}] Scoping not supported`);
            }
        }
    }


    static dumpThreads( pStatuts:string[] = []){
        const threads:ThreadDetails[] = Process.enumerateThreads();

        threads.map( (th)=>{
            if(pStatuts.length > 0){
                if(pStatuts.indexOf(th.state)==-1) return;
            }
            console.log(`Thread ID=${th.id} STATE=${th.state} : \n\t${Thread.backtrace(th.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`);
        });
    }
}