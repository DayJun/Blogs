import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSAUtil {
    //������Կ��
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    //��ȡ��Կ(Base64����)
    public static String getPublicKey(KeyPair keyPair){
        PublicKey publicKey = keyPair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        return byte2Base64(bytes);
    }

    //��ȡ˽Կ(Base64����)
    public static String getPrivateKey(KeyPair keyPair){
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        return byte2Base64(bytes);
    }

    //��Base64�����Ĺ�Կת����PublicKey����
    public static PublicKey string2PublicKey(String pubStr) throws Exception{
        byte[] keyBytes = base642Byte(pubStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    //��Base64������˽Կת����PrivateKey����
    public static PrivateKey string2PrivateKey(String priStr) throws Exception{
        byte[] keyBytes = base642Byte(priStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    //��Կ����
    public static byte[] publicEncrypt(byte[] content, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    //˽Կ����
    public static byte[] privateDecrypt(byte[] content, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    //�ֽ�����תBase64����
    public static String byte2Base64(byte[] bytes){
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(bytes);
    }

    //Base64����ת�ֽ�����
    public static byte[] base642Byte(String base64Key) throws IOException{
        BASE64Decoder decoder = new BASE64Decoder();
        return decoder.decodeBuffer(base64Key);
    }

    public static void main(String[] args){
        try {
            //===============���ɹ�Կ��˽Կ����Կ�����ͻ��ˣ�˽Կ����˱���==================
            //����RSA��Կ��˽Կ����Base64����
            KeyPair keyPair = RSAUtil.getKeyPair();
            String publicKeyStr = RSAUtil.getPublicKey(keyPair);
            String privateKeyStr = RSAUtil.getPrivateKey(keyPair);
            System.out.println("RSA��ԿBase64����:" + publicKeyStr);
            System.out.println("RSA˽ԿBase64����:" + privateKeyStr);

            //=================�ͻ���=================
            //hello, i am infi, good night!����
            String message = "hello, i am infi, good night!";
            //��Base64�����Ĺ�Կת����PublicKey����
            PublicKey publicKey = RSAUtil.string2PublicKey(publicKeyStr);
            //�ù�Կ����
            byte[] publicEncrypt = RSAUtil.publicEncrypt(message.getBytes(), publicKey);
            //���ܺ������Base64����
            String byte2Base64 = RSAUtil.byte2Base64(publicEncrypt);
            System.out.println("��Կ���ܲ�Base64����Ľ����" + byte2Base64);


            //##############	�����ϴ����������Base64�����Ĺ�Կ �� Base64�����Ĺ�Կ���ܵ�����     #################



            //===================�����================
            //��Base64������˽Կת����PrivateKey����
            PrivateKey privateKey = RSAUtil.string2PrivateKey(privateKeyStr);
            //���ܺ������Base64����
            byte[] base642Byte = RSAUtil.base642Byte(byte2Base64);
            //��˽Կ����
            byte[] privateDecrypt = RSAUtil.privateDecrypt(base642Byte, privateKey);
            //���ܺ������
            System.out.println("���ܺ������: " + new String(privateDecrypt));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
