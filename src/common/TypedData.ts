import {T} from "./Types";

export enum VAL_TYPE {
    CONSTANT,
    INOUT,
    OUTPUT
}

export class TypedData {
    t:number = T.UINT32;
    n:string = null;
    r:number = -1;
    l:number;
    f?:any;
    c:boolean = false;
    e?:any;
    len?:number; // size if l => BUFFER
    v?:number;

    constructor(pCfg:any = null) {
        if(pCfg != null){
            for(let i in pCfg) this[i] = pCfg[i];
        }
    }

    static from(pCfg:any){
        return new TypedData(pCfg);
    }

    static buffer(pType:TypedData, pSize:number =-1){
        return null; //pType.copy();
    }

    out(){
        return this.copy().update({ v: VAL_TYPE.OUTPUT });
    }

    update( pCfg:any){
        for(let i in pCfg){
            this[i] = pCfg[i];
        }
        return this;
    }

    copy( pName:string=null){
        let t:TypedData = new TypedData(this);
        if(pName!=null)  t.n = pName;
        return t;
    }

    asReturn( pError:any[]=[]){
        let t:TypedData = new TypedData(this);
        t.e = pError;
        return t;
    }
}