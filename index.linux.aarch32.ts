/**
 * The aim of this entrypoint is to offers Interruptor factory for Linux/Arm64
 *
 * It is particularly appropriate when Interruptor is used as a single included
 * file into a specific project
 *
 * @author georges@dexcalibur.org
 */
import {LinuxAarch32InterruptorFactory} from "./src/arch/LinuxAarch32InterruptorFactory";

export const target = {
    LinuxAarch32: function(pOptions:any){
        return new LinuxAarch32InterruptorFactory(pOptions);
    }
}
