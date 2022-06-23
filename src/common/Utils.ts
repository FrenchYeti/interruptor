export class Utils {

    static deepCopy(pSrcObject:any): any {
        const destObj = {};
        for(let i in pSrcObject){
            if(typeof pSrcObject[i] == 'object' && pSrcObject[i] !== null){
                destObj[i] = Utils.deepCopy(pSrcObject[i]);
            }else{
                destObj[i] = pSrcObject[i];
            }
        }
        return destObj;
    }
}

