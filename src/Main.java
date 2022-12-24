import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Scanner scanner = new Scanner(System.in);

        // Prompt the user to enter the message to encrypt or decrypt
        System.out.print("Enter the message to encrypt or decrypt: ");
        String input = scanner.nextLine();

        // Prompt the user to enter the key to use for the encryption/decryption
        System.out.print("Enter the key size to use for the encryption/decryption (128, 192 or 256): ");
        int keySize = Integer.valueOf(scanner.nextLine());
        SecretKey key = AES.generateKey(keySize);
        IvParameterSpec ivParameterSpec = AES.generateIv();

        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherText = AES.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AES.decrypt(algorithm, cipherText, key, ivParameterSpec);

        //Display
        System.out.println("Original: " + input);
        System.out.println("Encrypted: " + cipherText);
        System.out.println("Decrypted: " + plainText);
    }

}
