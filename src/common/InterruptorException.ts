export enum ErrorCode {
    GENERIC= 1000
}

export class MonitoredError extends Error {

    /**
     * Component name
     *
     * @field
     * @type string
     */
    cmp:string;
    code:number;
    extra:any;

    constructor( pCmp:string, pMsg:string, pCode:number = null, pExtra:any = null) {
        super(pMsg);
        this.cmp = pCmp;
        this.code = pCode;
        this.extra = pExtra;
    }

    getCode():number {
        return this.code;
    }


    getExtra():any {
        return this.extra;
    }

    toString():string {
        return `[${this.cmp}] [#${this.code!=null ? this.code : "<null>"} ${this.message}`;
    }

    /**
     *
     * @param pIncludeExtra
     */
    toObject(pIncludeExtra:boolean=false):any {
        return {
            cmp: this.cmp,
            code: this.code,
            msg: this.message,
            extra: pIncludeExtra ? this.extra : null
        }
    }
}


export class InterruptorGenericException extends MonitoredError {

    static ERR = {
        INVALID_PID: ErrorCode.GENERIC + 101,
        INVALID_TID: ErrorCode.GENERIC + 102,
        UKNOW_SYSCALL: ErrorCode.GENERIC + 103,
    };

    static INVALID_PID = ()=>{ return new InterruptorGenericException(" PID is invalid ",InterruptorGenericException.ERR.INVALID_PID) };
    static INVALID_TID = ()=>{ return new InterruptorGenericException(" Thread ID is invalid ",InterruptorGenericException.ERR.INVALID_TID) };
    static UNKNOW_SYSCALL = (sys)=>{ return new InterruptorGenericException(" Syscall '"+sys+"' not exists ",InterruptorGenericException.ERR.UKNOW_SYSCALL) };

    constructor( pMsg:string, pCode:number = null, pExtra:any = null) {
        super('GLOBAL', pMsg, pCode, pExtra);
    }
}