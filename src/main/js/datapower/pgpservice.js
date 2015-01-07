require('pgp/js/es6-promise').polyfill();

(function () {

    var pgpservice = {};

    pgpservice.baseurl = "http://10.8.5.8:8080/pgpservice/";

    var root, previous_pgpservice;

    root = this;
    if (root != null) {
        previous_pgpservice = root.pgpservice;
    }

    pgpservice.noConflict = function () {
        root.pgpservice = previous_pgpservice;
        return pgpservice;
    };

    var getURLResults = function (options) {
        return new Promise(function (resolve, reject) {
            // open connection to target and send data over
            require('urlopen').open(options, function (error, response) {
                if (error) {
                    // an error occurred during request sending or response header parsing
                    reject(Error("urlopen connect error: " + JSON.stringify(error)));
                } else {
                    // read response data
                    // get the response status code
                    var responseStatusCode = response.statusCode;
                    if (responseStatusCode == 200) {
                        response.readAsBuffer(function (error, responseData) {
                            if (error) {
                                // error while reading response or transferring data to Buffer
                                reject(Error("readAsBuffer error: " + JSON.stringify(error)));
                            } else {
                                resolve(responseData);
                            }
                        });
                    } else {
                        reject(Error("urlopen target return statusCode " + responseStatusCode));
                    }
                }
            });
        });
    }

    var readPassPhrase = function (company) {
        return new Promise(function (resolve, reject) {

            var options = {
                target: 'local:///pgp/keys/' + company + '.secret.passphrase'
            };

            getURLResults(options)
                .then(function (response) {
                    resolve(response);
                })
                .catch(function (error) {
                    reject(error);
                });
        });
    }

    var readPublicKey = function (company) {
        return new Promise(function (resolve, reject) {
            var options = {
                target: 'local:///pgp/keys/' + company + '.pub.asc'
            };

            getURLResults(options)
                .then(function (response) {
                    resolve(response);
                })
                .catch(function (error) {
                    reject(error);
                });
        });
    }

    var readPrivateKey = function (company) {
        return new Promise(function (resolve, reject) {
            var options = {
                target: 'local:///pgp/keys/' + company + '.secret.asc'
            };

            getURLResults(options)
                .then(function (response) {
                    resolve(response);
                })
                .catch(function (error) {
                    reject(error);
                });
        });
    }

    pgpservice.encryptData = function (tocompany, inputData) {
        return new Promise(function (resolve, reject) {

            var publickey = null;

            readPublicKey(tocompany)
                .then(function (response) {
                    publickey = response;

                    // Call webservice with information
                    var options = {
                        target: pgpservice.baseurl + 'encrypt',
                        method: 'post',
                        contentType: 'application/json',
                        timeout: 60,
                        data: {
                            "publickey": publickey.toString('base64'),
                            "armor": true,
                            "data": inputData.toString('base64')
                        }
                    };
                    return getURLResults(options);
                })
                .then(function (response) {
                    resolve(response);
                })
                .catch(function (error) {
                    reject(error);
                });
        });
    }

    pgpservice.encryptAndSignData = function (fromcompany, tocompany, inputData) {
        return new Promise(function (resolve, reject) {

            var privatekey = null;
            var passphrase = null;
            var publickey = null;

            readPrivateKey(fromcompany)
                .then(function (response) {
                    privatekey = response;
                    return readPassPhrase(fromcompany);
                })
                .then(function (response) {
                    passphrase = response;
                    return  readPublicKey(tocompany);
                })
                .then(function (response) {
                    publickey = response;

                    // Call webservice with information
                    var options = {
                        target: pgpservice.baseurl + 'encrypt',
                        method: 'post',
                        contentType: 'application/json',
                        timeout: 60,
                        data: {
                            "publickey": publickey.toString('base64'),
                            "armor": true,
                            "privatekey": privatekey.toString('base64'),
                            "sign": true,
                            "passphrase": passphrase.toString('utf-8'),
                            "data": inputData.toString('base64')
                        }
                    };
                    return getURLResults(options);
                })
                .then(function (response) {
                    resolve(response);
                })
                .catch(function (error) {
                    reject(error);
                });
        });
    }

    pgpservice.decryptAndVerifyData = function (tocompany, fromcompany, inputData) {
        return new Promise(function (resolve, reject) {

            // Call webservice with information
            var privatekey = null;
            var passphrase = null;
            var publickey = null;

            readPublicKey(fromcompany)
                .then(function (response) {
                    publickey = response;
                    return readPrivateKey(tocompany);
                })
                .then(function (response) {
                    privatekey = response;
                    return readPassPhrase(tocompany);
                })
                .then(function (response) {
                    passphrase = response;

                    // Call webservice with information
                    var options = {
                        target: pgpservice.baseurl + 'decrypt',
                        method: 'post',
                        contentType: 'application/json',
                        timeout: 60,
                        data: {
                            "publickey": publickey.toString('base64'),
                            "verifysignature": true,
                            "privatekey": privatekey.toString('base64'),
                            "passphrase": passphrase.toString('utf-8'),
                            "data": inputData.toString('base64')
                        }
                    };
                    return getURLResults(options);
                })
                .then(function (response) {
                    resolve(response);
                })
                .catch(function (error) {
                    reject(error);
                });
        });
    }
    pgpservice.decryptData = function (tocompany, inputData) {
        return new Promise(function (resolve, reject) {

            // Call webservice with information
            var privatekey = null;
            var passphrase = null;

            readPrivateKey(tocompany)
                .then(function (response) {
                    privatekey = response;
                    return readPassPhrase(tocompany);
                })
                .then(function (response) {
                    passphrase = response;

                    // Call webservice with information
                    var options = {
                        target: pgpservice.baseurl + 'decrypt',
                        method: 'post',
                        contentType: 'application/json',
                        timeout: 60,
                        data: {
                            "privatekey": privatekey.toString('base64'),
                            "passphrase": passphrase.toString('utf-8'),
                            "data": inputData.toString('base64')
                        }
                    };
                    return getURLResults(options);
                })
                .then(function (response) {
                    resolve(response);
                })
                .catch(function (error) {
                    reject(error);
                });
        });
    }

    // Node.js
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = pgpservice;
    }
    // AMD / RequireJS
    else if (typeof define !== 'undefined' && define.amd) {
        define([], function () {
            return pgpservice;
        });
    }
    else {
        root.pgpservice = pgpservice;
    }

}());
