package Test;
import java.math.BigInteger;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECPSignature;
import org.bouncycastle.util.encoders.Hex;
import wallet.Sign;

public class SignTest {
    public static void main(String[] args) {
        SECP256K1 secp256K1 = new SECP256K1();
        Sign sign = new Sign();
        BigInteger privateKey = new BigInteger("1"); // 使用固定的私钥
        byte[] message = "Hello, world!".getBytes(); // 要签名的消息
/*
        // 对消息进行签名
        byte[] signatureBytes = secp256K1.sign(message, privateKey);
        SECPSignature signature = SECPSignature.decodeFromDER(signatureBytes);
        System.out.println("Signature: " + signature);

        // 验证签名
        byte[] publicKeyBytes = sign.publicKeyBytesFromPrivate(privateKey, false);
        BigInteger publicKey = sign.publicFromPoint(publicKeyBytes);
        boolean valid = secp256K1.verify(message, signatureBytes, publicKey);
        System.out.println("Valid: " + valid);

 */
    }
}
