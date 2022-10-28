import {T} from "./Types.js";
import {IStringIndex} from "../utilities/IStringIndex.js";

export enum VAL_TYPE {
    CONSTANT,
    INOUT,
    OUTPUT
}

/**
 * @class
 */
export class TypedData implements IStringIndex {
    /**
     * Data type
     * See T
     * @field {string}
     */
    t:number = T.UINT32;

    /**
     * Type or arg name
     * @field {string}
     */
    n = "";

    /**
     * Register number holding extra value required to
     * interpret current data
     * @field {number}
     */
    r = -1;

    /**
     * Meaning of the value (conceptually) : file descriptor, pointer to struct, flags, ...
     * @field {Types.L}
     */
    l=-1;

    /**
     * Optional. If the mean of the data is specified, an extra value to help to parse
     * or the parser
     * @field {any}
     */
    f?:any;

    /**
     * A flag if the value is constant ('const' keyword).
     * Non-constant value can be updated bue the syscall.
     *
     * Default is FALSE
     * @field {boolean}
     */
    c = false;

    /**
     * Optional. The list of error codes which can be hold by this data.
     * It helps to define the type of return value.
     * @field {any}
     */
    e?:any;

    /**
     * The length of the data if the data is an array or a L.BUFFER
     * @type {number}
     * @field
     */
    len?:number; // size if l => BUFFER

    /**
     * The raw value
     * @type {number}
     * @field
     */
    v?:number;

    /**
     *
     * @param pCfg
     * @constructor
     */
    constructor(pCfg:any = null) {
        if(pCfg != null){
            for(const i in pCfg) (this as any)[i] = pCfg[i];
        }
    }

    /**
     *
     * @param pCfg {any} Config
     * @return {TypedData} An instance of TypedData
     * @method
     * @static
     */
    static from(pCfg:any){
        return new TypedData(pCfg);
    }

    static buffer(pType:TypedData, pSize =-1){
        return this; //pType.copy();
    }

    out(){
        return this.copy().update({ v: VAL_TYPE.OUTPUT });
    }

    update( pCfg:IStringIndex){
        for(const i in pCfg){
            (this as any)[i] = pCfg[i];
        }
        return this;
    }

    copy( pName=""){
        const t:TypedData = new TypedData(this);
        if(pName!="")  t.n = pName;
        return t;
    }

    constant(pConst = true){
        this.c  = pConst;
        return this;
    }

    asReturn( pError:any[]=[]){
        const t:TypedData = new TypedData(this);
        t.e = pError;
        return t;
    }
}