package com.clcomputing.openpgp.models;

public class EncryptRequest {
    public String publickey; // expecting base64
    public String privatekey; // expecting base64
    public boolean sign;
    public String passphrase;
    public boolean armor;
    public String data; // expecting base64
}
