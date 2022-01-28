const path = require('path');

module.exports = {
    entry: './dist/index.linux.arm64.js',
    // devtool: 'inline-source-map',
    target: 'node',
    mode: 'production',
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'android-arm64-strace.min.js',
        library: {
            //name: 'Interruptor',
            type: 'commonjs'
        }
    },
};