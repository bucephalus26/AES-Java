import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Implementation of the Advanced Encryption Standard (AES),
 * a symmetric-key encryption algorithm, via Java Cryptography
 * Architecture (JCA).
 *
 * @author Ibraheem Khan
 * @version 1.0
 */
public class AES {

    /**
     * Method for generating the secret key via KeyGenerator.
     * The KeyGenerator class (AES instance) uses SecureRandom to generate a Secure Random Number
     * with desired key size.
     *
     * @param keySize represents the AES key size (128, 192, and 256 bits).
     * @return generated SecretKey.
     * @throws NoSuchAlgorithmException if algorithm is not available.
     */
    public static SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /**
     * Method for generating the Initialization Vector (IV).
     * IV is a random value used to ensure identical plain texts
     * have distinct ciphertexts.
     *
     * @return generated Initialization Vector.
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Input is encrypted in this method.
     *
     * Class Cipher gives encryption functionality.
     * Cipher init method is used to initialize the Cipher instance with
     * the encryption operation mode. The key and IV are also specified.
     *
     * @param algorithm the algorithm to be used.
     * @param input the plaintext to-be encrypted.
     * @param key the SecretKey generated.
     * @param iv the Initialization Vector generated.
     * @return the ciphertext in bytes.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException if the key supplied in incorrect.
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        // Initialize the Cipher object for encryption
        Cipher cipher = Cipher.getInstance(algorithm);
        // ENCRYPT_MODE for encryption
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * Ciphertext is decrypted in this method.
     * This time Cipher instance is initialized with the decryption
     * operation mode.
     *
     * @param algorithm the algorithm to be used.
     * @param cipherText the ciphertext to-be encrypted.
     * @param key the SecretKey generated.
     * @param iv the Initialization Vector generated.
     * @return the decrypted plaintext.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException if the key supplied in incorrect.
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

}
