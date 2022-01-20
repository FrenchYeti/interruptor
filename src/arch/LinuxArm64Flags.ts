
const O_ = {
    O_ACCMODE: 0o00000003,
    O_RDONLY: 0o0000000,
    O_WRONLY: 0o0000001,
    O_RDWR	: 0o0000002,
    O_CREAT	: 0o0000100,
    O_EXCL	: 0o0000200,
    O_NOCTTY: 0o0000400,
    O_TRUNC	: 0o0001000,
    O_APPEND: 0o0002000,
    O_NONBLOCK: 0o0004000,
    O_DSYNC	: 0o0010000,
    FASYNC	: 0o0020000,
    O_DIRECT: 0o0040000,
    O_LARGEFILE: 0o0100000,
    O_DIRECTORY: 0o0200000,
    O_NOFOLLOW: 0o0400000,
    O_NOATIME: 0o1000000,
    O_CLOEXEC: 0o2000000
};

const MNT_ = {
    MNT_FORCE: 1,
    MNT_DETACH: 2,
    MNT_EXPIRE: 4,
    UMOUNT_NOFOLLOW: 8,
};
const PROT_NONE = 0;
const PROT_ = {
    PROT_READ: 1,
    PROT_WRITE: 2,
    PROT_EXEC: 4,
};

/**
 * A function to stringify bitmap
 */
function stringifyBitmap(val:number, flags:any):string{
    let s = "";
    for(const f in flags){
        if((val & flags[f]) == flags[f]) s += (s.length>0?" | ":"")+f;
    }

    return s;
}


export const X = {
    XATTR: function(f){
        return ["default","XATTR_CREATE","XATTR_REPLACE"][f];
    },
    ATTR: function(f){
        return f;
    },
    O_MODE: function(f){
        return stringifyBitmap(f,O_);
    },
    UMOUNT: function(f){
        return stringifyBitmap(f,MNT_);
    },
    MPROT: function(f){
        if(f == PROT_NONE)
            return "PROT_NONE";

        return stringifyBitmap(f,PROT_);
    },
}
