'use strict';

const ApiGateway = require('moleculer-web');
const { MoleculerError } = require('moleculer').Errors;
class UnauthorizedError extends MoleculerError {
    constructor() {
        super('Authorization Failure', 401, 'authorization-failure', []);
    }
}
module.exports = {
    name: 'host-api',
    mixins: [ApiGateway],
    settings: {
        cors: {
            origin: "*",
            methods: ["GET", "OPTIONS", "POST", "PUT", "DELETE"],
            allowedHeaders: [],
            exposedHeaders: [],
            credentials: false,
            maxAge: 3600
        },
        port: process.env.PORT || 3000,
        path: '/api',
        routes: [
            {
                path: '/public',
                authorization: false,
                mappingPolicy: 'restrict',
                mergeParams: true,
                aliases: {
                    // auth
                    'POST login': 'auth.login',
                    'POST register': 'auth.register',
                    'GET customer/provider_list': 'customer.providerList',
                    'GET customer/product_list': 'customer.productList',
                },
                bodyParsers: {
                    json: true
                }
            },
            {
                path: '/',
                authorization: true,
                mappingPolicy: 'restrict',
                mergeParams: true,
                aliases: {
                    'POST logout': 'auth.logout',
                    'POST change_password': 'auth.changepassword',
                    'GET user_info': 'customer.userInfo' , 
                    // CUSTOMER
                    'PUT customer/earn_money': 'customer.earnMoney',
                    
                    'GET customer/dashboard': 'customer.dashboard',
                    'GET customer/item_list': 'customer.itemList',
                    
                    'POST customer/buy_item': 'customer.buyItem',

                    // PROVIDER
                    'GET provider/shop_info': 'provider.shopInfo',
                    'POST provider/import_item': 'provider.importItem',
                    'PUT provider/create_shop': 'provider.createShop',
                    'GET provider/item_list': 'provider.itemList',
                    'DELETE provider/delete_item': 'provider.deleteItem',
                    'PUT provider/edit_item': 'provider.editItem',

                    //ADMIN
                    'GET admin/active/:activeToken': 'admin.activeToken',
                    'GET admin/approve_queue': 'admin.approveQueue',
                    'PUT admin/active_provider': 'admin.activeProvider',
                    'PUT admin/ban_provider': 'admin.banProvider',
                    'GET admin/user_list' : 'admin.userList'
                    
                },
                bodyParsers: {
                    json: true
                }
            },
        ],
        onError(req, res, err) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.writeHead(err.code <= 500 ? err.code : 500);
            res.end(JSON.stringify({
                code: err.code,
                message: err.code <= 500 ? err.message : 'internal-server-error',
                data: err.data
            }));
        },
        // Serve assets from "public" folder
        assets: {
            folder: 'public'
        },
        acceptedLanguages: ['vi', 'en', 'ja'],
        defaultLanguage: 'vi'
    },

    methods: {
        async authorize(ctx, route, req, res) {
            let auth = req.headers.authorization;
            let acceptLanguage = req.headers['accept-language'];
            if (!this.settings.acceptedLanguages.includes(acceptLanguage)) {
                acceptLanguage = this.settings.defaultLanguage;
            }
            ctx.meta.acceptLanguage = acceptLanguage;

            if (auth && auth.startsWith('Bearer')) {
                let user = await this.broker.call('auth.verifyToken', { token: auth });
                if(user === undefined){
                    console.log(user);
                    return Promise.reject(new UnauthorizedError());        
                }
                ctx.meta.user = user;
                return Promise.resolve(ctx);
            }
            // No token
            return Promise.reject(new UnauthorizedError());
        }
    },

    events: {
        'user.logout'(payload) {
            this.broker.cacher.del(payload.token);
            this.broker.cacher.del(`host_${payload.token}`);
        }
    }
};
