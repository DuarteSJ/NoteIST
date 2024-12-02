package pt.tecnico;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.google.gson.*;

/**
 * Example of JSON writer.
 */
public class SecureWriter {
    public static void main(String[] args) throws Exception {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", SecureWriter.class.getName());
            return;
        }
        final String filename = args[0];

        // Create bank statement JSON object
        JsonObject jsonObject = new JsonObject();

        JsonObject headerObject = new JsonObject();
        headerObject.addProperty("author", "Ultron");
        headerObject.addProperty("version", 2);
        headerObject.addProperty("title", "Age of Ultron");
        JsonArray tagsArray = new JsonArray();
        tagsArray.add("robot");
        tagsArray.add("autonomy");
        headerObject.add("tags", tagsArray);
        jsonObject.add("header", headerObject);

        jsonObject.addProperty("body", "I had strings but now I'm free");

        jsonObject.addProperty("status", "published");
        
        final String keyPath = "keys/secret.key";
        // read key
        System.out.println("Reading key from file " + keyPath + "...");
        Key key = readSecretKey(keyPath);

        //digest data
        final String DIGEST_ALGO = "SHA-256";
        System.out.println("Digesting with " + DIGEST_ALGO + "...");
        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);
        messageDigest.update(jsonObject.toString().getBytes());
        byte[] digestBytes = messageDigest.digest();
        System.out.println("Result: " + digestBytes.length + " bytes");

        String digestB64dString = Base64.getEncoder().encodeToString(digestBytes);
        System.out.println("Digest result, encoded as base 64 string: " + digestB64dString);

        // cipher digest

        final String CIPHER_ALGO = "AES/ECB/PKCS5Padding";
        System.out.println("Ciphering with " + CIPHER_ALGO + "...");
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherBytes = cipher.doFinal(digestBytes);
        System.out.println("Result: " + cipherBytes.length + " bytes");

        String cipherB64dString = Base64.getEncoder().encodeToString(cipherBytes);
        System.out.println("Cipher result, encoded as base 64 string: " + cipherB64dString);

        //write the file 
        try (FileWriter fileWriter = new FileWriter(filename)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            jsonObject.addProperty("cipher", cipherB64dString);
            gson.toJson(jsonObject, fileWriter);
        }

        // Write JSON object to file
        try (FileWriter fileWriter = new FileWriter(filename)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(jsonObject, fileWriter);
        }
    }
    private static byte[] readFile(String path) throws FileNotFoundException, IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] content = new byte[fis.available()];
        fis.read(content);
        fis.close();
        return content;
    }

    public static Key readSecretKey(String secretKeyPath) throws Exception {
        byte[] encoded = readFile(secretKeyPath);
        SecretKeySpec keySpec = new SecretKeySpec(encoded, "AES");
        return keySpec;
    }
}
