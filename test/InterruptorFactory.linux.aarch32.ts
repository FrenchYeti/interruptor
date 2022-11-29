import {LinuxAarch32InterruptorFactory} from "../src/arch/LinuxAarch32InterruptorFactory.js";
import { expect } from 'chai';

describe('[LINUX][AARCH32] InterruptorFactory tests', () => { // the tests container


    describe('* Basic features', () => {

        const factory = new LinuxAarch32InterruptorFactory();

        it('checking default factory', () => {
            expect(factory.getOptions()).to.be.null;
        });

        it('checking built-in utilities', () => {
            const utils = factory.utils();

            expect(Object.keys(utils).length).to.be.greaterThan(0);
            expect(Object.values(utils).length).to.be.greaterThan(0);

            expect(utils.toByteArray).to.be.a('function');
            expect(utils.toScanPattern).to.be.a('function');
            expect(utils.printBackTrace).to.be.a('function');
        });
    });

    describe('* Kernel API constants', () => {

        const factory = new LinuxAarch32InterruptorFactory();

        it('Error Codes', () => {
            /*
                EPERM : [1,"Not super-user"],
                ENOENT : [2,"No such file or directory"],
                ESRCH : [3,"No such process"],
                EINTR : [4,"Interrupted system call"],
                EIO : [5,"I/O error"],
             */
            expect(factory.KAPI.ERR).to.be.not.null;
            expect(Object.keys(factory.KAPI.ERR).length).to.be.greaterThan(120);
            expect(factory.KAPI.ERR.EPERM).to.be.equal(1);
            expect(factory.KAPI.ERR.ENOENT).to.be.equal(2);
            expect(factory.KAPI.ERR.ESRCH).to.be.equal(3);
            expect(factory.KAPI.ERR.EINTR).to.be.equal(4);
            expect(factory.KAPI.ERR.EIO).to.be.equal(5);
        });

    });


});
