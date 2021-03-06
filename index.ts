/**
 * The aim of this entrypoint is to offers Interruptor factory for each arch/os supported.
 *
 * It is particularly appropriate when Interruptor package is installed globally (npm install -g)
 *
 * @author georges@dexcalibur.org
 */
import {LinuxArm64InterruptorFactory} from "./src/arch/LinuxArm64InterruptorFactory";

export const target = {
    LinuxArm64: function(pOptions:any){
        return new LinuxArm64InterruptorFactory(pOptions);
    }
}