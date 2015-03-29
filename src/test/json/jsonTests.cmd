curl -X POST -T decrypt.json http://10.8.5.8:8080/pgpservice/decrypt
curl -X POST -T decryptVerify.json http://10.8.5.8:8080/pgpservice/decrypt
curl -X POST -T encrypt.json http://10.8.5.8:8080/pgpservice/encrypt
curl -X POST -T encryptSign.json http://10.8.5.8:8080/pgpservice/encrypt