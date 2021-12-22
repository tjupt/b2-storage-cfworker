const Dotenv = require('dotenv-webpack')

module.exports = {
  entry: './src/index.js',
  mode: 'production',
  optimization: {
    minimize: true,
  },
  performance: {
    hints: 'error',
  },
  plugins: [new Dotenv()],
  output: {
    path: __dirname + '/dist',
    publicPath: 'dist',
    filename: 'worker.js',
  },
  resolve: {
    fallback: {
      crypto: false,
    },
  },
}
