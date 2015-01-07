package com.clcomputing.openpgp.models;

public class DecryptRequest {
    public String publickey; // expecting base64
    public boolean verifysignature;
    public String privatekey; // expecting base64
    public String passphrase;
    public String data; // expecting base64
}
