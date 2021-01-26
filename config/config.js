'use strict';

// const configFirebase = require('./firebase.json');

module.exports = {
    JWT_SECRET: process.env.JWT_SECRET || 'JWT_SECRET',
    JWT_REFRESH_SECRET: process.env.JWT_SECRET || 'JWT_REFRESH_SECRET'
    // FIREBASE: configFirebase
};
