var pgpservice = require('pgp/js/pgpservice');


session.input.readAsBuffer(function (error, buffer) {

    if (error) {
        throw error;
    }

    var sm = require ('service-metadata');
    var fromID = sm.getVar ('var://service/b2b-partner-from');
    var toID = sm.getVar ('var://service/b2b-partner-to');

    pgpservice.decryptAndVerifyData(toID, fromID, buffer)
        .then(function (response) {
            session.output.write(response);
        })
        .catch(function (error) {
            throw error;
        });


});
