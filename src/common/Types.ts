/**
 * The aim of this interface is to describe CPU-specific data required
 * to retrieve and parse sys call from  CPU context.
 *
 * @interface
 * @export
 */
import {IStringIndex} from "../utilities/IStringIndex";

export interface SyscallCallingConvention extends IStringIndex {
    /**
     * The mmemonic of the opcode performing the interruption
     * Example : 'swi' for armv7
     * @type string
     * @field
     */
    OP: string;

    /**
     * The name of the register holding the syscall number
     * Example : 'r7' for armv7
     * @type string
     * @field
     */
    NR: string;

    /**
     * The name of the register holding the error code / return value after the syscall
     * Example : 'r7' for armv7
     * @type string
     * @field
     */
    RET: string;

    /**
     * The name of the register holding the 1st arg
     * Example : 'r0' for armv7
     * @type string
     * @field
     */
    ARG0: string;

    /**
     * The name of the register holding the 2nd arg
     * Example : 'r1' for armv7
     * @type string
     * @field
     */
    ARG1: string;

    /**
     * The name of the register holding the 3rd arg
     * Example : 'r2' for armv7
     * @type string
     * @field
     */
    ARG2: string;

    /**
     * The name of the register holding the 4th arg
     * Example : 'r3' for armv7
     * @type string
     * @field
     */
    ARG3: string;

    /**
     * The name of the register holding the 5th arg
     * Example : 'r4' for armv7
     * @type string
     * @field
     */
    ARG4: string;

    /**
     * The name of the register holding the 6th arg
     * Example : 'r5' for armv7
     * @type string
     * @field
     */
    ARG5: string;

    /**
     * The name of the register holding the program counter / current instruction
     * Example : 'pc' for armv7 , 'EIP', ...
     * @type string
     * @field
     */
    PC: string;
}

export type SyscallNumber = number;
export type SyscallName = string;
export type ErrorCodeName = string;
export type ErrorCodeConst = number;




/**
 * To hold extra data for the hook context
 * @interface
 */
interface ExtraContext {
    orig?:NativePointer;
    FD?:any;
    WD?:any;
    SOCKFD?:any;
    DFD?:any;
    [name:string] :any;
}

export interface RichCpuContext {
    dxc?:ExtraContext;
    log?:string;
    dxcOpts?:any;
    dxcRet?:any;
}

/**
 * Basic interface to define an error code
 * @interface
 */
export interface ErrorCode {
    0: ErrorCodeConst;
    1: string;
    2?: ErrorCodeName;
}

export interface ErrorCodeList extends IStringIndex {
    [name:string] :ErrorCode;
}

export interface ErrorCodeMapping extends IStringIndex {
    [name:string] :number;
}

export interface SyscallInOutInfo extends IStringIndex{
    t:T;
    n?:SyscallName;
    l?:L;
    f?:any;
    r?:string|number|(string|number)[];
    c?:boolean;
    e?:ErrorCode[]
}

export interface SyscallInInfo extends SyscallInOutInfo{
     t:T;
     n:SyscallName;
}

export interface SyscallOutInfo extends SyscallInOutInfo{
    t:T;
    e:ErrorCode[]
}

export interface SyscallOutMap extends IStringIndex {
    [shortcut:string] :SyscallOutInfo;
}

export type SyscallParamSignature = SyscallInInfo | string;

export interface SyscallHook {
    onEnter?: ((ctx:RichCpuContext)=>void);
    onLeave?: ((ctx:RichCpuContext)=>void);
}

export interface SyscallHookMap {
    [syscallName:string] : SyscallHook;
}


export enum SyscallInfo {
    NUM,
    NAME,
    HEX,
    ARGS,
    RET
}

export interface SyscallSignature {
    0: SyscallNumber;
    1: SyscallName;
    2: SyscallNumber;
    3: SyscallParamSignature[];
    4?: SyscallOutInfo;
}

export interface SyscallMapping {
    [name:string] :SyscallSignature;
}

export type InterruptSignature = SyscallSignature;


export interface InterruptSignatureMap {
    syscalls: SyscallSignature[] | null,
    [type:string] :InterruptSignature[] | null
}

export enum F {
    EXCLUDE_ANY,
    INCLUDE_ANY,
    FILTER
}

/**
 * The aim of this enumeration is to provide a list of meaning to help
 * to analyse syscall's arguments and provide useful information
 *
 * @enum
 * @export
 */
export enum L {
    PATH,
    SIZE,
    FD, // File Descriptor
    DFD, // Directory File Descriptor
    FLAG,
    ATTRMODE,
    O_FLAGS,
    VADDR,
    MPROT,
    OUTPUT_BUFFER,
    PID,
    ERR,
    SIG,
    XATTR_LIST,
    F_,
    MFD, // Mapped FD
    UID,
    GID,
    UTSNAME,
    FCNTL_ARGS, // fnctl() args
    FCNTL_RET, // fnctl() ret
    TIME, // Timestamp
    INODE, // Inode
    DEV, // Device
    DSTRUCT,
    EPFD, // EPoll File Descriptor
    WD,// Watch Descriptor,
    PIPEFD, // fd[2] read FD, write FD
    SOCKFD,
    BUFFER,
    PKEY,
    IDSTRUCT,
    FUTEX,
    TIMER,
    MQDES,// struct always parsed,
    PTRACE

}

/**
 * An enumeration of most basic type, most of them are primitive type.
 *
 * @enum
 * @export
 */
export enum T {
    INT32,
    UINT32,
    LONG,
    ULONG,
    SHORT,
    USHORT,
    FLOAT,
    DOUBLE,
    CHAR,
    STRING,
    CHAR_BUFFER,
    POINTER32,
    POINTER64,
    STRUCT
}
