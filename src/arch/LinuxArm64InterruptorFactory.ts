/**

 @author Georges-Bastien Michel <georges@reversense.com>
 @copyright Reversense SAS

 */
import {InterruptorGenericException} from "../common/InterruptorException";
import {InterruptorAgent} from "../common/InterruptorAgent";
import {AbstractInterruptorFactory} from "../common/AbstractInterruptorFactory";
import {LinuxArm64InterruptorAgent} from "./LinuxArm64InterruptorAgent";



export class LinuxArm64InterruptorFactory extends AbstractInterruptorFactory {


    //agents: InterruptorAgent[] = null;

    constructor( pOptions:any = null) {
        super(pOptions);
    }

    utils(){
        return {
            toScanPattern: AbstractInterruptorFactory.toScanPattern
        };
    }

    /**
     * To create a new Frida agent
     * @param pConfig
     */
    newAgentTracer(pConfig: any):InterruptorAgent {
        //const agent = new LinuxArm64InterruptorAgent(pConfig);

        return new LinuxArm64InterruptorAgent(pConfig);
    }


    newStandaloneTracer(){
        return null ;
    }


}
