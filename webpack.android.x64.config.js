import * as  path from 'path';
import * as  url from 'url';

const __dirname = url.fileURLToPath(new URL('.', import.meta.url));
const outputPath = path.resolve(__dirname, process.env.DXC_DIST ? 'dist':'.');

const config = {
    entry: './index.linux.x64.js',
    // devtool: 'inline-source-map',
    //target: 'node',
    mode: 'production',
    output: {
        path: outputPath,
        filename: 'android-x64-strace.min.js',
        library: {
            //name: 'Interruptor',
            type: 'commonjs'
        }
    },
    experiments: {
        outputModule: true
    }
};

export default config;