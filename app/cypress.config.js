import codeCoverageTasks from '@cypress/code-coverage/task.js'
import webpack from '@cypress/webpack-preprocessor'
import { defineConfig } from 'cypress'
import { rm } from 'fs/promises'

export default defineConfig({
  video: false,
  defaultCommandTimeout: 10000,
  viewportWidth: 1280,
  viewportHeight: 1024,
  e2e: {
    // We've imported your old cypress plugins here.
    // You may want to clean this up later by importing these.
    setupNodeEvents(on, config) {
      on(
        'file:preprocessor',
        webpack({
          webpackOptions: {
            module: {
              rules: [
                {
                  test: /.js$/,
                  use: 'babel-loader',
                },
              ],
            },
          },
        })
      ),
        codeCoverageTasks(on, config)
      on('task', {
        /**
         * @param {string} path
         */
        async rm(path) {
          await rm(path, { recursive: true, force: true })
          return null
        },
      })
      return config
    },
    baseUrl: 'http://localhost:8080',
  },
})
