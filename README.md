YAR
===

Yet Another RSA PKCS#1 implementation.

### Keys generation: ###
#### Plain Java: ####
```
try {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair kp = keyGen.generateKeyPair();
} catch (NoSuchAlgorithmException e) {
    //
}
```

#### YAR: ####
```
YarKeyPair kp = YarKeyPairGenerator.generateKeyPair(2048);
```

### Encryption: ###
#### Plain Java: ####
```
String message = "Help the bombardier!";
byte[] cipherData;
try {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
    cipherData = cipher.doFinal(message.getBytes());
} catch (NoSuchAlgorithmException e) {
    //
} catch (NoSuchPaddingException e) {
    //
} catch (InvalidKeyException e) {
    //
} catch (BadPaddingException e) {
    //
} catch (IllegalBlockSizeException e) {
    //
}
```

#### YAR: ####
```
byte[] cipherData = Yar.encrypt(message, kp.getPublicKey());
```

### Decryption: ###
#### Plain Java: ####
```
String clearText;
try {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
    byte[] data = cipher.doFinal(cipherData);
    clearText = new String(data);
} catch (NoSuchAlgorithmException e) {
    //
} catch (NoSuchPaddingException e) {
    //
} catch (InvalidKeyException e) {
    //
} catch (BadPaddingException e) {
    //
} catch (IllegalBlockSizeException e) {
    //
}
```

#### YAR: ####
```
byte[] data = Yar.decrypt(encrypted, kp.getPrivateKey());
String clearText = new String(data);
```

### Signature generation: ###
#### Plain Java: ####
```
byte[] signature;
try {
    Signature instance = Signature.getInstance("SHA256withRSA");
    instance.initSign(kp.getPrivate());
    instance.update(message.getBytes());
    signature = instance.sign();
} catch (NoSuchAlgorithmException e) {
    //
} catch (SignatureException e) {
    //
} catch (InvalidKeyException e) {
    //
}
```

#### YAR: ####
```
byte[] signature = Yar.sign(message, kp.getPrivateKey(), HashMethod.SHA_256);
```

### Signature verification: ###
#### Plain Java: ####
```
boolean result;
try {
    Signature instance = Signature.getInstance("SHA256withRSA");
    instance.initVerify(kp.getPublic());
    instance.update(message.getBytes());
    result = instance.verify(signature);
} catch (NoSuchAlgorithmException e) {
    //
} catch (SignatureException e) {
    //
} catch (InvalidKeyException e) {
    //
}
```

#### YAR: ####
```
boolean result = Yar.verify(message, signature, kp.getPublicKey(), HashMethod.SHA_256)
```
