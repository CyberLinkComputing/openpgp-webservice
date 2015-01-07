var pgpservice = require('pgp/js/pgpservice');


session.input.readAsBuffer(function (error, buffer) {

    if (error) {
        throw error;
    }

    pgpservice.decryptData("DPOW", buffer)
        .then(function (response) {
            session.output.write(response);
        })
        .catch(function (error) {
            throw error;
        });


});
