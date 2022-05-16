import {TypedData} from "./TypedData";

export interface TypeDefList {
    [typeName:string] :TypeDef
}

export class TypeDef {

    t:TypedData[];

    constructor(pDefine:any = [], pCopy = false) {
        this.t = [];
        pDefine.map(( data)=>{
            this.t.push( pCopy ? data : (new TypedData(data)) );
        });
    }

    getStruct():TypedData[] {
        return this.t;
    }
}