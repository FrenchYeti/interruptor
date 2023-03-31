import {IStringIndex} from "../utilities/IStringIndex";
import {ErrorCodeMapping, SyscallMapping} from "../common/Types.js";

export interface KernelConstant {
    /**
     * Constant value
     * @field
     */
    0: number;
    /**
     * Constant name
     * @string
     */
    1?:string;
}

export interface KernelEnum {
    [constName:string] :KernelConstant;
}

export interface KernelConstMapping {
    [constName:string] :KernelEnum|KernelConstMapping;
}

export interface KernelAPI {
    CONST: KernelConstMapping;
    SYSC: SyscallMapping;
    ERR:ErrorCodeMapping;
}