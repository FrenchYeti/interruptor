import {T} from "./Types";

export class TypedData {
    t:number = T.UINT32;
    n:string = null;
    r:number = -1;
    l:number;
    f?:any;
    c:boolean = false;
    e?:any;

    constructor(pCfg:any = null) {
        if(pCfg != null){
            for(let i in pCfg) this[i] = pCfg[i];
        }
    }

    static from(pCfg:any){
        return new TypedData(pCfg);
    }

    copy( pName:string){
        let t:TypedData = new TypedData(this);
        t.n = pName;
        return t;
    }

    asReturn( pError:any[]){
        let t:TypedData = new TypedData(this);
        t.e = pError;
        return t;
    }
}