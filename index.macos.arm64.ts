/**
 * The aim of this entrypoint is to offers Interruptor factory for MacOS/Arm64
 *
 * It is particularly appropriate when Interruptor is used as a single included
 * file into a specific project
 *
 * @author georges@dexcalibur.org
 */
import {MacosArm64InterruptorFactory} from "./src/arch/MacosArm64InterruptorFactory.js";

const target = {
    MacosArm64: function(pOptions:any){
        return new MacosArm64InterruptorFactory(pOptions);
    }
}

export default target;
