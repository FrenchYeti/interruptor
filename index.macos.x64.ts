/**
 * The aim of this entrypoint is to offers Interruptor factory for MacOS/x64
 *
 * It is particularly appropriate when Interruptor is used as a single included
 * file into a specific project
 *
 * @author georges@dexcalibur.org
 */
import {MacosX64InterruptorFactory} from "./src/arch/MacosX64InterruptorFactory.js";

const target = {
    MacosArm64: function(pOptions:any){
        return new MacosX64InterruptorFactory(pOptions);
    }
}

export default target;
