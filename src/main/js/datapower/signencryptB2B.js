var pgpservice = require('pgp/js/pgpservice');


session.input.readAsBuffer(function (error, buffer) {

    if (error) {
        throw error;
    }

    var ctx = session.name('message');
    var toID = ctx.getVar('b2bto');
    var fromID = ctx.getVar('b2bfrom');

    pgpservice.encryptAndSignData(fromID, toID, buffer)
        .then(function (response) {
            session.output.write(response);
        })
        .catch(function (error) {
            throw error;
        });


});
