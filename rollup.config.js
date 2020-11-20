import replace from 'rollup-plugin-replace'
import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'
import alias from 'rollup-plugin-alias'
import { terser } from 'rollup-plugin-terser'
import path from 'path'
import rimraf from 'rimraf'
import pascalcase from 'pascalcase'

const cwd = process.cwd()
// eslint-disable-next-line
const pkg = require(path.join(cwd, 'package.json'))

rimraf.sync(path.join(cwd, './dist'))

const banner = `/*!
  * ${pkg.name} v${pkg.version}
  * (c) ${new Date().getFullYear()} Gabin Desserprit
  * @license MIT
  */`

const exportName = pascalcase(pkg.name)

function createEntry(
  {
    format, // Rollup format (iife, umd, cjs, es)
    input = 'src/index.js', // entry point
    external = [],
    env = 'development', // NODE_ENV variable
    minify = false,
    isBrowser = false, // produce a browser module version or not
  } = {
    input: 'src/index.js',
    env: 'development',
    minify: false,
    isBrowser: false,
  }
) {
  // force production mode when minifying
  if (minify) env = 'production'

  const config = {
    input,
    plugins: [
      replace({
        __VERSION__: pkg.version,
        'process.env.NODE_ENV': `'${env}'`,
      }),
      alias({
        resolve: ['.js'],
      }),
    ],
    output: {
      banner,
      file: `dist/${pkg.name}.UNKNOWN.js`,
      format,
    },
  }

  if (format === 'iife') {
    config.output.file = pkg.unpkg
    config.output.name = exportName
  } else if (format === 'es') {
    config.output.file = pkg.module
  } else if (format === 'cjs') {
    config.output.file = pkg.main
  } else if (format === 'umd') {
    config.output.name = exportName
    config.output.file = pkg.browser
  }

  if (!external) {
    config.plugins.push(commonjs(), resolve())
  } else {
    config.external = external
  }

  if (minify) {
    config.plugins.push(
      terser({
        module: format === 'es',
        // output: {
        //   preamble: banner,
        // },
      })
    )
    config.output.file = config.output.file.replace(/\.js$/i, '.min.js')
  }

  return config
}

const builds = [createEntry({ format: 'cjs' }), createEntry({ format: 'umd', isBrowser: true })]

if (pkg.unpkg) builds.push(createEntry({ format: 'iife' }), createEntry({ format: 'es' }))

export default builds
