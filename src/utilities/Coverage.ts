import {InterruptorAgent} from "../common/InterruptorAgent";


export class CoverageAgent {


    /**
     * Number of bits in a byte
     */
    static BITS_PER_BYTE = 8;
    /**
     * Mask to select the value of a single byte
     */
    static BYTE_MASK = 0xFF;
    /**
     * Number of bytes in an unsigned 16 bit number
     */
    static BYTES_PER_U16 = 2;
    /**
     * Number of bytes in an unsigned 32 bit number
     */
    static BYTES_PER_U32 = 4;
    /**
     * The fixed character width of the module base field output for each module in the coverage header.
     */
    static COLUMN_WIDTH_MODULE_BASE = 16;
    /**
     * The fixed character width of the module checksum field output for each module in the coverage header.
     */
    static COLUMN_WIDTH_MODULE_CHECKSUM = 16;
    /**
     * The fixed character width of the module end field output for each module in the coverage header.
     */
    static COLUMN_WIDTH_MODULE_END = 16;
    /**
     * The fixed character width of the module entry field output for each module in the coverage header.
     */
    static COLUMN_WIDTH_MODULE_ENTRY = 16;
    /**
     * The fixed character width of the module id field output for each module in the coverage header.
     */
    static COLUMN_WIDTH_MODULE_ID = 3;
    /**
     * The fixed character width of the module timestamp field output for each module in the coverage header.
     */
    static COLUMN_WIDTH_MODULE_TIMESTAMP = 8;
    /**
     * The array index of the compile event end field in the StalkerCompileEventFull
     */
    static COMPILE_EVENT_END_INDEX = 2;
    /**
     * The array index of the compile event start field in the StalkerCompileEventFull
     */
    static COMPILE_EVENT_START_INDEX = 1;
    /**
     * The value of the type field in the StalkerCompileEventFull
     */
    static COMPILE_EVENT_TYPE = "compile";
    /**
     * The array index of the compile event type field in the StalkerCompileEventFull
     */
    static COMPILE_EVENT_TYPE_INDEX = 0;
    /**
     * The byte offset of the module id field within the DRCOV event structure
     */
    static EVENT_MODULE_OFFSET = 6;
    /**
     * The byte offset of the size field within the DRCOV event structure
     */
    static EVENT_SIZE_OFFSET = 4;
    /**
     * The byte offset of the start field within the DRCOV event structure
     */
    static EVENT_START_OFFSET = 0;
    /**
     * The total size in bytes of the DRCOV event structure
     */
    static EVENT_TOTAL_SIZE = 8;

    enabled:boolean = false;
    interruptor:InterruptorAgent = null;
    flavor:string = "dr";
    fname:string = null; // "drcov.dat";
    events: Map<number,number> = new Map();
    threads: any[] = [];
    onCoverage: any = ()=>{};
    out:any = null;
    stops: any = {count: Infinity};




    constructor( pInterruptor:any) {
        this.interruptor = pInterruptor;
    }

    static from( pConfig:any, pInterruptor:any):CoverageAgent {
        const agent = new CoverageAgent(pInterruptor);
        for(let i in pConfig){
            switch(i){
                case 'fname':
                    agent.fname = pConfig.fname;
                    break;
                case 'enabled':
                    agent.enabled = pConfig.enabled;
                    break;
                case 'format':
                    agent.flavor = pConfig.flavor;
                    break;
                case 'stops':
                    agent.stops = pConfig.stops;
                    break;
                case 'onCoverage':
                    agent.onCoverage = pConfig.onCoverage;
                    break;
            }
        }
        return agent;
    }

    initOutput():void {
        if(this.fname != null){
            this.out = new File(this.fname, "wb+");
            console.log("[COVERAGE] Create file : "+this.fname);
        }
    }

    emit(coverageData:any){
        (this.onCoverage)(coverageData);
        if(this.out != null){
            try{
                this.out.write(coverageData);
            }catch(e){
               // console.error("[COVERAGE] Write failed : "+e.message);
            }
        }

    }

    processStalkerEvent( pEvent:any) {
        const type = pEvent[CoverageAgent.COMPILE_EVENT_TYPE_INDEX];
        if (type.toString() === CoverageAgent.COMPILE_EVENT_TYPE.toString()) {
            const start = pEvent[CoverageAgent.COMPILE_EVENT_START_INDEX];
            const end = pEvent[CoverageAgent.COMPILE_EVENT_END_INDEX];
            this.events.set(start, end);

            /*if(this.isStepReached()){

            }*/

            if(this.isStopReached()){
                this.stop();
            }
        }
    }

    isStopReached(){
        return (this.events.size >= this.stops.count);
    }

    isStepReached(){
        return (this.stops.step > -1) && (this.events.size % this.stops.step == 0);
    }

    // From frida-drcov

    /**
     * Function to convert an ANSI string into an ArrayBuffer
     *
     * @param data The string to convert
     * @returns An array buffer containing the raw string data
     */
    static convertString(data) {
        const buf = new ArrayBuffer(data.length);
        const view = new Uint8Array(buf);
        for (let i = 0; i < data.length; i += 1) {
            view[i] = data.charCodeAt(i);
        }
        return buf;
    }
    /**
     * Function to left pad a string with a repeating pattern. If the pattern is not a multiple of the padding required
     * to make the output the correct length, then the last copy of the padding before the original string will be
     * truncated.
     * @param data The input string to be padded
     * @param length The required length of the output
     * @param pad The value which should be prepended to the string until it is the requested length
     * @returns The padded input string, padding to the requested length
     */
    static padStart(data, length, pad) {
        const paddingLength = length - data.length;
        const partialPadLength = paddingLength % pad.length;
        const fullPads = paddingLength - partialPadLength / pad.length;
        const result = pad.repeat(fullPads) + pad.substring(0, partialPadLength)
            + data;
        return result;
    }
    /**
     * Function to write a 16-bit value in little-endian format to a given address. Note that DRCOV format data is
     * always in little endian, regardless the endian-ness of the target application.
     *
     * @param address The address at which to write the value
     * @param value The value to be written
     */
    static write16le(address, value) {
        let i;
        for (i = 0; i < CoverageAgent.BYTES_PER_U16; i += 1) {
            // tslint:disable-next-line:no-bitwise
            const byteValue = (value >> (CoverageAgent.BITS_PER_BYTE * i)) & CoverageAgent.BYTE_MASK;
            address.add(i)
                .writeU8(byteValue);
        }
    }
    /**
     * Function to write a 32-bit value in little-endian format to a given address. Note that DRCOV format data is
     * always in little endian, regardless the endian-ness of the target application.
     *
     * @param address The address at which to write the value
     * @param value The value to be written
     */
    static write32le(address, value) {
        let i;
        for (i = 0; i < CoverageAgent.BYTES_PER_U32; i += 1) {
            // tslint:disable-next-line:no-bitwise
            const byteValue = (value >> (CoverageAgent.BITS_PER_BYTE * i)) & CoverageAgent.BYTE_MASK;
            address.add(i)
                .writeU8(byteValue);
        }
    }
    /**
     * Stop the collection of coverage data
     */
    stop() {
        /*
        this.threads.forEach((t) => {
            Stalker.unfollow(t.id);
        });
        Stalker.flush();*/

        const eventList = Array.from(this.events.entries());
        const convertedEvents = eventList.map(([start, end]) => this.convertEvent(start, end));
        const nonNullEvents = convertedEvents.filter((e) => e !== undefined);
        this.emitHeader(nonNullEvents.length);
        for (const convertedEvent of nonNullEvents) {
            if (convertedEvent !== undefined) {
                this.emitEvent(convertedEvent);
            }
        }


        if(this.out != null){
            this.out.close();
            this.out = null;
            console.warn("[COVERAGE] Output file "+this.fname+" closed !")
        }
    }
    /**
     * Function used to covert a coverage event, when called with parameters parsed from
     * StalkerCompileEventFull in the 'onRecevied' function of stalker.
     *
     * @param start The address of the start of the compiled block.
     * @param end The address of the end of the compile block.
     */
    convertEvent(start, end) {
        for (let i = 0; i < this.interruptor.modules.length; i += 1) {
            const base = this.interruptor.modules[i].base;
            const size = this.interruptor.modules[i].size;
            const limit = base.add(size);
            if (start.compare(base) < 0) {
                continue;
            }
            if (end.compare(limit) > 0) {
                continue;
            }
            const offset = start.sub(base)
                .toInt32();
            const length = end.sub(start)
                .toInt32();
            if (!this.isInRange(base, start, end)) {
                return undefined;
            }
            const event = {
                length,
                moduleId: i,
                offset,
            };
            return event;
        }
        return undefined;
    }
    /**
     * Function used to emit a coverage event, when called with parameters parsed from StalkerCompileEventFull in the
     * 'onRecevied' function of stalker.
     *
     * @param event The event to emit
     */
    emitEvent(event) {
        /*
         * struct {
         *     guint32 start;
         *     guint16 size;
         *     guint16 mod_id;
         * };
         */
        const memory = Memory.alloc(CoverageAgent.EVENT_TOTAL_SIZE);
        CoverageAgent.write32le(memory.add(CoverageAgent.EVENT_START_OFFSET), event.offset);
        CoverageAgent.write16le(memory.add(CoverageAgent.EVENT_SIZE_OFFSET), event.length);
        CoverageAgent.write16le(memory.add(CoverageAgent.EVENT_MODULE_OFFSET), event.moduleId);
        const buf = ArrayBuffer.wrap(memory, CoverageAgent.EVENT_TOTAL_SIZE);
        this.emit(buf);
    }
    /**
     * Function to emit the header information at the start of the DRCOV coverage information format. Note that the
     * format includes a number of events in the header. This is obviously not ideally suited to streaming data, so we
     * instead write the value of -1. This does not impair the operation of dragondance (which ignores the field), but
     * changes may be required for IDA lighthouse to accept this modification.
     * @param events The number of coverage events emitted in the file
     */
    emitHeader(events) {
        this.emit(CoverageAgent.convertString("DRCOV VERSION: 2\n"));
        this.emit(CoverageAgent.convertString("DRCOV FLAVOR: frida\n"));
        this.emit(CoverageAgent.convertString(`Module Table: version 2, count ${this.interruptor.modules.length}\n`));
        this.emit(CoverageAgent.convertString("Columns: id, base, end, entry, checksum, timestamp, path\n"));
        this.interruptor.modules.forEach((m, idx) => {
            this.emitModule(idx, m);
        });
        this.emit(CoverageAgent.convertString(`BB Table: ${events} bbs\n`));
    }
    /**
     * Function to emit information about a given module into the header information of the DRCOV coverage information
     * format.
     *
     * @param idx The index of the module
     * @param module The module information
     */
    emitModule(idx, module) {
        const moduleId = CoverageAgent.padStart(idx.toString(), CoverageAgent.COLUMN_WIDTH_MODULE_ID, " ");
        let base = module.base
            .toString(16);
        base = CoverageAgent.padStart(base, CoverageAgent.COLUMN_WIDTH_MODULE_BASE, "0");
        let end = module.base
            .add(module.size)
            .toString(16);
        end = CoverageAgent.padStart(end, CoverageAgent.COLUMN_WIDTH_MODULE_END, "0");
        const entry = "0".repeat(CoverageAgent.COLUMN_WIDTH_MODULE_ENTRY);
        const checksum = "0".repeat(CoverageAgent.COLUMN_WIDTH_MODULE_CHECKSUM);
        const timeStamp = "0".repeat(CoverageAgent.COLUMN_WIDTH_MODULE_TIMESTAMP);
        const path = module.path;
        const elements = [moduleId, base, end, entry, checksum, timeStamp, path];
        const line = elements.join(", ");
        this.emit(CoverageAgent.convertString(`${line}\n`));
    }
    /**
     * Function to determine whether a coverage event resides in a valid range
     * associated with a given module.
     * @param base The base address of the module
     * @param start The start of the basic block
     * @param end The end of the basic block
     */
    isInRange(base, start, end) {
        const ranges = this.interruptor.ranges.get(base);
        if (ranges === undefined) {
            return false;
        }
        for (const range of ranges) {
            if (end.compare(range.base) < 0) {
                continue;
            }
            const limit = range.base.add(range.size);
            if (start.compare(limit) >= 0) {
                continue;
            }
            return true;
        }
        return false;
    }
}