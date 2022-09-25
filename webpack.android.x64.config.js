const path = require('path');
const outputPath = path.resolve(__dirname, process.env.DXC_DIST ? 'dist':'.');

module.exports = {
    entry: './index.linux.x64.js',
    // devtool: 'inline-source-map',
    target: 'node',
    mode: 'production',
    output: {
        path: outputPath,
        filename: 'android-x64-strace.min.js',
        library: {
            //name: 'Interruptor',
            type: 'commonjs'
        }
    },
};