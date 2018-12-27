'use strict';
import { NativeModules } from 'react-native';
var Q = require('q');

export default class RestClient {

    constructor (baseUrl = '', { headers = {},sslconfig = {}, timeout = 15000, devMode = false, simulatedDelay = 0 } = {}) {
        if (!baseUrl) throw new Error('missing baseUrl');
        this.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        };
        Object.assign(this.headers, headers);
        this.sslconfig = sslconfig;
        this.timeout = timeout;
        this.baseUrl = baseUrl;
        this.simulatedDelay = simulatedDelay;
        this.devMode = devMode;
    }

    fetch(url, obj, callback) {
        var deferred = Q.defer();
        NativeModules.RNHttpsPlugin.fetch(url, obj, (err, res) => {
            if (err) {
                deferred.reject(err);
            } else {
                res.json = function() {
                    return Q.fcall(function () {
                        return JSON.parse(res.bodyString);
                    });
                };
                res.text = function() {
                    return Q.fcall(function () {
                        return res.bodyString;
                    });
                };
                res.url = url;
                deferred.resolve(res);
            }
            deferred.promise.nodeify(callback);
        });
        return deferred.promise;
    }

    _simulateDelay () {
        return new Promise(resolve => {
            setTimeout(() => {
                resolve();
            }, this.simulatedDelay);
        });
    }

    _fullRoute (url) {
        return `${this.baseUrl}${url}`;
    }

    _fetch (route, method, body, isQuery = false) {
        if (!route) throw new Error('Route is undefined');
        var fullRoute = this._fullRoute(route);
        if (isQuery && body) {
            var qs = require('qs');
            const query = qs.stringify(body);
            fullRoute = `${fullRoute}?${query}`;
            body = undefined;
        }
        let opts = {
            method,
            headers: this.headers,
            body,
            sslconfig: this.sslconfig,
            timeout: this.timeout
        };
        if (opts.body) {
            Object.assign(opts, { body: JSON.stringify(opts.body) });
        }
        const fetchPromise = () => this.fetch(fullRoute, opts);
        if (this.devMode && this.simulatedDelay > 0) {
            // Simulate an n-second delay in every request
            return this._simulateDelay()
                .then(() => fetchPromise())
                .then(response => response.json());
        } else {
            return fetchPromise()
                .then(response => response.json());
        }
    }

    GET (route, query) { return this._fetch(route, 'GET', query, true); }
    POST (route, body) { return this._fetch(route, 'POST', body); }
    PUT (route, body) { return this._fetch(route, 'PUT', body); }
    DELETE (route, query) { return this._fetch(route, 'DELETE', query, true); }
}

