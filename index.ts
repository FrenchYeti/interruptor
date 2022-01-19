import {LinuxArm64InterruptorFactory} from "./src/arch/LinuxArm64InterruptorFactory";

const Interruptors = {
    LinuxArm64: function(pOptions:any){
        return new LinuxArm64InterruptorFactory(pOptions);
    }
}

export default Interruptors;