package org.example;

import org.example.utils.EncryptionUtil;

public class TestEncryption {
    public static void main(String[] args) {
        try {
            String originalData = "This is a secret message.";

            // Encrypt the data
            String encryptedData = EncryptionUtil.encrypt(originalData);
            System.out.println("Encrypted Data: " + encryptedData);

            // Decrypt the data
            String decryptedData = EncryptionUtil.decrypt(encryptedData);
            System.out.println("Decrypted Data: " + decryptedData);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}