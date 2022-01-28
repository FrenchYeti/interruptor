

/**
 * Abstract class
 *
 * Must be used to implement additional architecture
 *
 *  @class
 */
export abstract class AbstractInterruptorFactory {

    opts:any = null;

    static toScanPattern(pString:string):string {
        return pString.split('').map( c => c=c.charCodeAt(0).toString(16)).join(' ');
    }

    constructor(pOptions:any) {
        this.opts = pOptions;
    }

    abstract newAgentTracer(pConfig:any);

    abstract newStandaloneTracer(pConfig:any);

    getOptions():any {
        return this.opts;
    }

}