package com.clcomputing.datapower.openpgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.*;
import java.util.Date;
import java.util.Iterator;

public class Processor {

    static final int BUFFER_SIZE = 1 << 16;

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input));

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    /**
     * Search a secret key ring collection for a secret key corresponding to keyID if it
     * exists.
     *
     * @param pgpSec     a secret key ring collection.
     * @param keyID      keyID we want.
     * @param passPhrase passphrase to decrypt secret key with.
     * @return
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] passPhrase)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }
        Provider provider = Security.getProvider("BC");
        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider(provider).build()).setProvider(provider).build(passPhrase));
    }

    /**
     * decrypt the passed in message stream
     */
    public static void decrypt(
            OutputStream os,
            InputStream in,
            PGPSecretKeyRingCollection pgpSec,
            char[] passwd
    )
            throws IOException, NoSuchProviderException {
        in = PGPUtil.getDecoderStream(in);

        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(in);
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            try (InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey))) {
                PGPObjectFactory plainFact = new PGPObjectFactory(clear);
                Object message = plainFact.nextObject();

                if (message instanceof PGPCompressedData) {
                    PGPCompressedData cData = (PGPCompressedData) message;
                    PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());

                    message = pgpFact.nextObject();
                }

                if (message instanceof PGPLiteralData) {
                    PGPLiteralData ld = (PGPLiteralData) message;
                    try (InputStream unc = ld.getInputStream()) {
                        Streams.pipeAll(unc, os);
                    }
                } else if (message instanceof PGPOnePassSignatureList) {
                    throw new PGPException("encrypted message contains a signed message - not literal data.");
                } else {
                    throw new PGPException("message is not a simple encrypted file - type unknown.");
                }

                if (pbe.isIntegrityProtected()) {
                    if (!pbe.verify()) {
                        System.err.println("message failed integrity check");
                    } else {
                        System.err.println("message integrity check passed");
                    }
                } else {
                    System.err.println("no message integrity check");
                }
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    public static void encrypt(
            OutputStream out,
            InputStream input,
            PGPPublicKey encKey,
            boolean armor
    )
            throws IOException, NoSuchProviderException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        try {
            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

            cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            try (OutputStream cOut = cPk.open(out, new byte[BUFFER_SIZE])) {
                PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                        PGPCompressedData.ZIP);

                PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
                try (OutputStream pOut = lData.open(comData.open(cOut), PGPLiteralData.BINARY, "", new Date(), new byte[BUFFER_SIZE])) {
                    Streams.pipeAll(input, pOut);
                }
                comData.close();
            }
            if (armor) {
                out.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }


    public static void signAndEncrypt(OutputStream out, InputStream in, PGPPublicKey encKey, PGPSecretKeyRingCollection pgpSecCol, boolean armor, boolean withIntegrityCheck, char[] pass) throws IOException, NoSuchProviderException {

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {
            PGPEncryptedDataGenerator encGen =
                    new PGPEncryptedDataGenerator(
                            new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(
                                    new SecureRandom())
                                    .setProvider("BC"));
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            try (OutputStream encryptedOut = encGen.open(out, new byte[BUFFER_SIZE]))
            {

            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            try (OutputStream compressedData = comData.open(encryptedOut)) {

                PGPPrivateKey pgpPrivKey = null;
                PGPSecretKey pgpSec = null;

                // Get first private key
                Iterator it2 = pgpSecCol.getKeyRings();
                while (pgpPrivKey == null && it2.hasNext()) {
                    PGPSecretKeyRing secRing = (PGPSecretKeyRing) it2.next();
                    Provider provider = Security.getProvider("BC");
                    pgpSec = secRing.getSecretKey();
                    pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider(provider).build()).setProvider(provider).build(pass));
                }

                if (pgpPrivKey == null) {
                    throw new IllegalArgumentException("secret key for message not found.");
                }

                PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
                        pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

                sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

                Iterator it = pgpSec.getPublicKey().getUserIDs();
                if (it.hasNext()) {
                    PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                    spGen.setSignerUserID(false, (String) it.next());
                    sGen.setHashedSubpackets(spGen.generate());
                }

                sGen.generateOnePassVersion(false).encode(compressedData); // bOut

                PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
                try (OutputStream lOut = lGen.open(compressedData, PGPLiteralData.BINARY, "output.txt", new Date(),
                        new byte[BUFFER_SIZE])) {
                    int ch;

                    while ((ch = in.read()) >= 0) {
                        lOut.write(ch);
                        sGen.update((byte) ch);
                    }
                }
                lGen.close();
                sGen.generate().encode(compressedData);
                comData.close();
            }
            }
            encGen.close();

            if (armor) {
                out.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        } catch (SignatureException e) {
            System.err.println(e);
        }
    }

    public static void decryptAndVerifySignature(OutputStream fOut, InputStream in, PGPPublicKeyRingCollection pgpRing, PGPSecretKeyRingCollection pgpSec, char[] passwd) throws IOException, SignatureException, PGPException,NoSuchProviderException {
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Unable to find secret key to decrypt the message");
        }

        InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

        PGPObjectFactory plainFact = new PGPObjectFactory(clear);

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData;

        Object message = plainFact.nextObject();
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

        while (message != null) {
            System.out.println(message.toString());
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream());
                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                // have to read it and keep it somewhere.
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            } else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        actualOutput.close();
        PGPPublicKey publicKey = null;
        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null || signatureList == null) {
            throw new PGPException("Poor PGP. Signatures not found.");
        } else {

            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature ops = onePassSignatureList.get(0);
                System.out.println("verifier : " + ops.getKeyID());

                publicKey = pgpRing.getPublicKey(ops.getKeyID());
                if (publicKey != null) {
                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                    ops.update(output);
                    PGPSignature signature = signatureList.get(i);
                    if (ops.verify(signature)) {
                        Iterator<?> userIds = publicKey.getUserIDs();
                        while (userIds.hasNext()) {
                            String userId = (String) userIds.next();
                            System.out.println(String.format("Signed by {%s}", userId));
                        }
                        System.out.println("Signature verified");
                    } else {
                        throw new SignatureException("Signature verification failed");
                    }
                }
            }

        }

        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            throw new PGPException("Data is integrity protected but integrity is lost.");
        } else if (publicKey == null) {
            throw new SignatureException("Signature not found");
        } else {
            fOut.write(output);
            fOut.flush();
            fOut.close();
        }
    }

}
