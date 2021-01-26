const knex = require('knex');

const environment = process.env.NODE_ENV || 'development';
const config = require('../knexfile')[environment];

class KnexConnection {
    static get knex() {
        if (!this.knexInstance) {
            this.knexInstance = knex(config);
        }
        return this.knexInstance;
    }
}

module.exports = KnexConnection.knex;
