/**
 * Abstract class
 *
 * Must be used to implement additional architecture
 *
 *  @class
 */
import {TypeDef, TypeDefList} from "./TypeDef.js";
import {InterruptorAgent} from "./InterruptorAgent.js";


export abstract class AbstractInterruptorFactory {

    typeDefs:TypeDefList = {};
    opts:any = null;
    static _tcolors: number[] = [0];

    static toScanPattern(pString:string):string {
        return pString.split('').map( c => c=c.charCodeAt(0).toString(16)).join(' ');
    }

    /**
     * To convert a string as a byte array, with optional padding
     *
     * @param pString
     * @param pSize
     * @param pPadding
     *
     */
    static toByteArray(pString:string, pSize=-1, pPadding = 0):number[] {
        const arr:number[] = pString.split('').map( c => c.charCodeAt(0));
        if(pSize>-1 && pSize>pString.length){
            do{ arr.push(pPadding) }while(arr.length < pSize-1);
        }
        return arr;
    }

    static printBackTrace(pContext:any):void {
        console.log(Thread.backtrace(pContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
    }

    static replaceHook( pSyscallName:string, pNewHooks:any ):void {
        // todo : replace + Stalker.invalidate()
    }

    constructor(pOptions:any) {
        this.opts = pOptions;
    }


    /**
     * To pick a random color to highlight line/thread
     *
     * @param pTID {number}
     * @return number A color number
     */
    static _pickThreadColor():number {
        let color;
        do{
            color = Math.floor( Math.random()*20)+31; //+30; //+30;
        }while(AbstractInterruptorFactory._tcolors.indexOf(color)>-1);
        AbstractInterruptorFactory._tcolors.push(color);
        return color;
        // this.output._threads[tid] = this._pickThreadColor();
    }

    abstract newAgentTracer(pConfig:any):InterruptorAgent;

    //abstract newStandaloneTracer(pConfig:any):InterruptorAgent;

    getOptions():any {
        return this.opts;
    }

    newTypeDefinition(pTypes:any):TypeDefList {
        this.typeDefs = {};

        for(const i in pTypes){
            this.typeDefs[i] = new TypeDef(pTypes[i]);
        }

        return this.typeDefs;
    }

}