package wallet;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.hyperledger.besu.crypto.SECP256K1;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.hyperledger.besu.crypto.SECPSignature;

public class Sign {

    public static final String Curve_Name = "secp256k1";
    public static final X9ECParameters Curve_Params = CustomNamedCurves.getByName(Curve_Name);
    //get Curve G point N-number of point, H is a factor
    public static final ECDomainParameters Curve = new ECDomainParameters(
            Curve_Params.getCurve(),
            Curve_Params.getG(),
            Curve_Params.getN(),
            Curve_Params.getH());
    public final SECP256K1 secp256K1 = new SECP256K1();
    public static BigInteger Half_Curve_Order = Curve_Params.getN().shiftRight(1);

    //decompress Publickey to (X,Y-low-bit);
    public static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(Curve.getCurve()));
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        return Curve.getCurve().decodePoint(compEnc);
    }

    //Return public key from private key;
    public static BigInteger publicKeyFromPrivate(BigInteger privateKey) {
        ECPoint point = publicPointFromPrivate(privateKey);
        byte[] encoded = point.getEncoded(false);
        return new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
    }

    //Return public key's point from private key;
    public static ECPoint publicPointFromPrivate(BigInteger privateKey) {
        if (privateKey.bitLength() > Curve.getN().bitLength()) {
            privateKey = privateKey.mod(Curve.getN());
        }
        return new FixedPointCombMultiplier().multiply(Curve.getG(), privateKey);
    }

    //From private key to public key's bytes;
    public static byte[] publicKeyBytesFromPrivate(BigInteger privatekey, boolean compressed) {
        ECPoint point = publicPointFromPrivate(privatekey);
        return point.getEncoded(compressed);
    }

    //From public point to public key;
    public static BigInteger publicFromPoint(byte[] bits) {
        return new BigInteger(1, Arrays.copyOfRange(bits, 1, bits.length));
    }

    //
    public static void verifyPrecondition(boolean assertionResult, String errprMsg) {
        if (!assertionResult) {
            throw new RuntimeException(errprMsg);
        }
    }

    public static SECPSignature toCanonical(SECPSignature signature) {
        if (signature.getS().compareTo(Half_Curve_Order) > 0) {
            return SECPSignature.create(signature.getR(), Curve.getN().subtract(signature.getS()), (byte) 0, Curve.getN());
        }
        return signature;
    }


}