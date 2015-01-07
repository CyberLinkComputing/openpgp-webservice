package com.clcomputing.datapower.openpgp.controllers;

import com.clcomputing.datapower.openpgp.models.DecryptRequest;
import com.clcomputing.datapower.openpgp.models.EncryptRequest;
import com.clcomputing.datapower.openpgp.Processor;
import com.google.gson.Gson;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.encoders.Base64;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;

@Path("/pgpservice")
public class PGPServiceController implements Serializable {

    @POST
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Path("encrypt")
    public byte[] encrypt(String json) {

        Gson gson = new Gson();
        EncryptRequest request = gson.fromJson(json, EncryptRequest.class);

        try (ByteArrayInputStream key = new ByteArrayInputStream(Base64.decode(request.publickey.getBytes()))) {
            PGPPublicKey publicKey = Processor.readPublicKey(key);

            try (ByteArrayInputStream is = new ByteArrayInputStream(Base64.decode(request.data.getBytes()))) {
                try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
                    if (request.sign) {
                        try (ByteArrayInputStream secretkey = new ByteArrayInputStream(Base64.decode(request.privatekey.getBytes()))) {
                            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretkey));
                            Processor.signAndEncrypt(os, is, publicKey, pgpSec, request.armor, true, request.passphrase.toCharArray());
                        }
                    } else {
                        Processor.encrypt(os, is, publicKey, request.armor);
                    }
                    return os.toByteArray();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @POST
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Path("decrypt")
    public byte[] decrypt(String json) {

        Gson gson = new Gson();
        DecryptRequest request = gson.fromJson(json, DecryptRequest.class);

        try (ByteArrayInputStream key = new ByteArrayInputStream(Base64.decode(request.privatekey.getBytes()))) {
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(key));
            try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
                try (ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(request.data.getBytes()))) {

                    if (request.verifysignature) {
                        try (ByteArrayInputStream publickey = new ByteArrayInputStream(Base64.decode(request.publickey.getBytes()))) {
                            PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publickey));
                            Processor.decryptAndVerifySignature(os, bis, pgpRing, pgpSec, request.passphrase.toCharArray());
                        }
                    } else {
                        Processor.decrypt(os, bis, pgpSec, request.passphrase.toCharArray());
                    }
                    return os.toByteArray();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
