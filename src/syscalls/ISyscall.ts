import {L, T} from "../common/Types.js";

export interface ParamSignature {
    t: T;
    n?: string;
    l?: L;
    f?: any;
    c?: boolean; // const
    r?: number|string;
}

type SyscallParam = string | ParamSignature;


const SVC_NUM = 0;
const SVC_NAME = 1;
const SVC_ARG = 3;
const SVC_RET = 4;
const SVC_ERR = 5;

export enum SyscallInfo {
    NUM=0,
    NAME=1,
    ARG=3,
    RET=4,
    ERR=5
}

export interface ReturnSignature extends ParamSignature{
    e?: number[]; // error code
}

export interface SyscallSignature {
    0: number;
    1: string;
    2: number;
    3: SyscallParam[];
    4?: ReturnSignature;
}

export interface SyscallMap {
    [sysName:string] :SyscallSignature
}
export interface SyscallHandlersMap {
    [sysNum:number] :SyscallSignature
}