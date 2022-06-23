/**
 * The aim of this entrypoint is to offers Interruptor factory for Linux/Arm64
 *
 * It is particularly appropriate when Interruptor is used as a single included
 * file into a specific project
 *
 * @author georges@dexcalibur.org
 */
import {LinuxX64InterruptorFactory} from "./src/arch/LinuxX64InterruptorFactory";

export const target = {
    LinuxX64: function(pOptions:any){
        return new LinuxX64InterruptorFactory(pOptions);
    }
}
