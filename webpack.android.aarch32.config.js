const path = require('path');
const outputPath = path.resolve(__dirname, process.env.DXC_DIST ? 'dist':'.');

module.exports = {
    entry: './index.linux.aarch32.js',
    // devtool: 'inline-source-map',
    target: 'node',
    mode: 'production',
    output: {
        path: outputPath,
        filename: 'android-aarch32-strace.min.js',
        library: {
            //name: 'Interruptor',
            type: 'commonjs'
        }
    },
};