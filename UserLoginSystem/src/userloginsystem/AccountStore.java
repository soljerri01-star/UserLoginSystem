/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package userloginsystem;

import java.io.*;
import java.nio.file.*;
import java.util.Properties;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class AccountStore {

    private static final Path FILE = Paths.get(
        System.getProperty("user.home"),
        "UserLoginSystem_accounts.properties"
    );

    public static boolean register(String username, String password) {
        if (username == null || password == null
                || username.trim().isEmpty()
                || password.isEmpty()) {
            return false;
        }

        try {
            Properties accounts = new Properties();

            if (Files.exists(FILE)) {
                try (InputStream in = Files.newInputStream(FILE)) {
                    accounts.load(in);
                }
            }

            String key = username.trim().toLowerCase();

            if (accounts.containsKey(key)) {
                return false;
            }

            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            String saltText = Base64.getEncoder()
                    .encodeToString(salt);

            String hash = hashPassword(password, salt);

            accounts.setProperty(
                key, saltText + ":" + hash
            );

            try (OutputStream out = Files.newOutputStream(FILE)) {
                accounts.store(out, "User Login System Accounts");
            }

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean authenticate(
            String username, String password) {

        if (username == null || password == null) {
            return false;
        }

        try {
            Properties accounts = new Properties();

            if (!Files.exists(FILE)) {
                return false;
            }

            try (InputStream in = Files.newInputStream(FILE)) {
                accounts.load(in);
            }

            String stored = accounts.getProperty(
                username.trim().toLowerCase()
            );

            if (stored == null) {
                return false;
            }

            String[] parts = stored.split(":");

            if (parts.length != 2) {
                return false;
            }

            byte[] salt = Base64.getDecoder()
                    .decode(parts[0]);

            String expected = hashPassword(password, salt);

            return MessageDigest.isEqual(
                expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                parts[1].getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

  
private static String hashPassword(
        String password, byte[] salt) throws Exception {

    javax.crypto.spec.PBEKeySpec spec =
        new javax.crypto.spec.PBEKeySpec(
            password.toCharArray(), salt, 65536, 256
        );

    try {
        byte[] hash = javax.crypto.SecretKeyFactory
            .getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec)
            .getEncoded();

        return java.util.Base64.getEncoder()
            .encodeToString(hash);

    } finally {
        spec.clearPassword();
    }
}

    
}




