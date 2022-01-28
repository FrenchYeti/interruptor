/**
 * The aim of this entrypoint is to offers Interruptor factory for Linux/Arm64
 *
 * It is particularly appropriate when Interruptor is used as a single included
 * file into a specific project
 *
 * @author georges@dexcalibur.org
 */
import {LinuxArm64InterruptorFactory} from "./src/arch/LinuxArm64InterruptorFactory";

export const target = {
    LinuxArm64: function(pOptions:any){
        return new LinuxArm64InterruptorFactory(pOptions);
    }
}
