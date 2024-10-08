#!/usr/bin/env node
'use strict'
import { injectSpeedInsights } from '@vercel/speed-insights';
const express = require('express')
const morgan = require('morgan')
const authenticate = require('./src/authenticate')
const params = require('./src/params')
const proxy = require('./src/proxy')

const app = express()
const PORT = process.env.PORT || 443

// use vercel Speed Insights
injectSpeedInsights();

// HTTP request logging
app.use(morgan('combined'))

app.enable('trust proxy')
app.get('/', authenticate, params, proxy)
app.get('/favicon.ico', (req, res) => res.status(204).end())
app.listen(PORT, () => {
    console.log(`Listening on ${PORT}`)
    // For additional setup like initializing performance monitoring agents, add here.
})
