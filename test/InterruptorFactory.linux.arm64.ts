import {LinuxArm64InterruptorFactory} from "../src/arch/LinuxArm64InterruptorFactory.js";
import { expect } from 'chai';

describe('[LINUX][AARCH64] InterruptorFactory tests', () => { // the tests container


    describe('* Basic features', () => {

        const factory = new LinuxArm64InterruptorFactory();

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

        const factory = new LinuxArm64InterruptorFactory();
        //const KAPI = factory.KAPI;

        it('Error Codes', () => {
            expect(factory.KAPI).to.be.null;
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


});
