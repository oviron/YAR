package com.oviron.yar;

public enum HashMethod {
    MD2("MD2", new byte[]{
            (byte) 0x30, (byte) 0x20, (byte) 0x30, (byte) 0x0c,
            (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
            (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d,
            (byte) 0x02, (byte) 0x02, (byte) 0x05, (byte) 0x00,
            (byte) 0x04, (byte) 0x10
    }),
    MD5("MD5", new byte[]{
            (byte) 0x30, (byte) 0x20, (byte) 0x30, (byte) 0x0c,
            (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
            (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d,
            (byte) 0x02, (byte) 0x05, (byte) 0x05, (byte) 0x00,
            (byte) 0x04, (byte) 0x10
    }),
    SHA_1("SHA-1", new byte[]{
            (byte) 0x30, (byte) 0x21, (byte) 0x30, (byte) 0x09,
            (byte) 0x06, (byte) 0x05, (byte) 0x2b, (byte) 0x0e,
            (byte) 0x03, (byte) 0x02, (byte) 0x1a, (byte) 0x05,
            (byte) 0x00, (byte) 0x04, (byte) 0x14
    }),
    SHA_256("SHA-256", new byte[]{
            (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
            (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
            (byte) 0x04, (byte) 0x02, (byte) 0x01, (byte) 0x05,
            (byte) 0x00, (byte) 0x04, (byte) 0x20
    }),
    SHA_384("SHA-384", new byte[]{
            (byte) 0x30, (byte) 0x41, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
            (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
            (byte) 0x04, (byte) 0x02, (byte) 0x02, (byte) 0x05,
            (byte) 0x00, (byte) 0x04, (byte) 0x30
    }),
    SHA_512("SHA-512", new byte[]{
            (byte) 0x30, (byte) 0x51, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
            (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
            (byte) 0x04, (byte) 0x02, (byte) 0x03, (byte) 0x05,
            (byte) 0x00, (byte) 0x04, (byte) 0x40
    });
    public final String name;
    public final byte[] prefix;

    HashMethod(String name, byte[] prefix) {
        this.name = name;
        this.prefix = prefix;
    }
}
