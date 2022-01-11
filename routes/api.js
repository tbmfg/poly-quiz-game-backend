const express = require('express');
const api = express.Router();

const v1Route = require('./v1/init');
const authRoute = require('./auth/auth');

api.use('/v1', v1Route);
api.use('/auth', authRoute);

module.exports = api;
