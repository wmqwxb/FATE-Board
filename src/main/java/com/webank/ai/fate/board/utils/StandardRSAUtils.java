package com.webank.ai.fate.board.utils;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Hello RSA!
 */
public class StandardRSAUtils {

    /**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";

    /**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 245;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 256;

    /**
     * <p>
     * 生成密钥对(公钥和私钥)
     * </p>
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * <p>
     * 用私钥对信息生成数字签名
     * </p>
     *
     * @param msg        已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String sign(String msg, String privateKey) throws Exception {
        byte[] data = msg.getBytes();
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * <p>
     * 校验数字签名
     * </p>
     *
     * @param msg       已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @return
     * @throws Exception
     */
    public static boolean verify(String msg, String publicKey, String sign)
            throws Exception {
        byte[] data = msg.getBytes();
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.getDecoder().decode(sign));
    }

    /**
     * <P>
     * 私钥解密
     * </p>
     *
     * @param encryptedDataStr 已加密数据
     * @param privateKey       私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(String encryptedDataStr, String privateKey)
            throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedDataStr);
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return new String(decryptedData);
    }

    /**
     * <p>
     * 公钥解密
     * </p>
     *
     * @param encryptedDataStr 已加密数据
     * @param publicKey        公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String decryptByPublicKey(String encryptedDataStr, String publicKey)
            throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedDataStr);
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return new String(decryptedData);
    }

    /**
     * <p>
     * 公钥加密
     * </p>
     *
     * @param msg       源数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String msg, String publicKey)
            throws Exception {
        byte[] data = msg.getBytes();
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();

        String encryptedDataStr = Base64.getEncoder().encodeToString(encryptedData);
        return encryptedDataStr;
    }

    /**
     * <p>
     * 私钥加密
     * </p>
     *
     * @param msg        源数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKey(String msg, String privateKey)
            throws Exception {
        byte[] data = msg.getBytes();
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();

        String encryptedDataStr = Base64.getEncoder().encodeToString(encryptedData);
        return encryptedDataStr;
    }

    /**
     * <p>
     * 获取私钥
     * </p>
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * <p>
     * 获取公钥
     * </p>
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static void main(String[] args) throws Exception {
        Map<String, Object> stringObjectMap = genKeyPair();
        String p = getPrivateKey(stringObjectMap);
        String k = getPublicKey(stringObjectMap);
        p = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCTnfJJtBKDvbKOUXLXr27IuL6bopSwBJUIE/viPa5L4zmw6f+13mxkfA98TbAKZeR8AI3Mtwuex9r8sLLRFC/00Qg/gUrvKTYFZMXZFfZpNB9kXUbCsAsnxor4B7RPj2hmGE5S6lBnOmkkmoTdp/1gF8K6c/pGXovgzebDpmnB03OKcTV2AsdS4A7quBYduYHGxZsoZyRdiFOzrU/our/pmGoPaX3P6sZRcWo+uBg2i0bo+hwkUDiguocDHvm+uQ1+laXeHVvI5rLXxRqCMAwNMWCB2kPmYgAsOW1iK9G5/iNUMyQJgWSO6LtXdG4sx6jD9vm2iUm/SKFNPj58fvxHAgMBAAECggEAGWaLQ21t5idlKyIOvdhdGsLXYZZ3OVaAgnRV2lc8v6gozC1np9bPFfdW/s+rZA6mY0QBImG46SiAoQySqHFt0xWI8sx/pWmU9xahCLrDvNSQNkfqniOGt+BtF0LUHwCROUgjahcRoMGnR/oitLVsXvWXt1evkB5CuXsUo0PmXMiP2owzW4cAl0cDxOrXmbGCWOW7RU9pSd2SO6/awlfAKakZRzLseIccuIx5EnfJIWfQNJlZizDfJ4PRZDfQM9L9pvSYSBF/akuxMYSIp9TMGGX2RZ9J/EFWRzmM3CB2YxpNX4mC7ZbTA1rq1aaHm+Pl7oibG44G1tF3Hj0QTobgWQKBgQDKrzHf8aQHnY00SJ8KTyFGfYXgXCP7U17a5Mxz0vQYf26VcRwZBXvI79H91pZOU3Yujf/bvcxZPjbNBkRJBuz1HB4bFoz4anYekMrQmPUSnZZXxGAZ2nWDJ5YFULM2eedRs1PE5lWLou1O41ffXlHQ8YWKGrmtX4IKlSv87HOXkwKBgQC6coDfy6SwLKZBuGYsMHTcxbeWaDnW2wPanwXC81OvK0xWapWucguH3ZbCoHTiN99HnBJVi6rXri2IXML7GEuNC/KTmF+dgtO/xIsj7IMBrAjYwm+d/cYQ5yF8gazaR0UM1iHC/0OImfEokICYd7VATibZMAvCfiSSmBqko7MQ/QKBgQCECQ8fiOXHRD6JUcmxSI0vw3OkDcIu5kfDpwr9ZO44y0L5vV6FekoCQyB0EQeHbN1vRHfp6UGm3V2LwEpZnFZe8ns2QEGDTq82CDLnIs173Ablk/ravLKSxwX23nRwx4cGdSDcAwS1W2TmYDmNPH9l8wCAUBqnM7GePUETmeFPWwKBgERS0YcxSRiGRCaxPD/VQf3lNnGXoBpsB+2FeMcIBBKc+0xvoopaoH8ZZLXNtwdvEhNbzhwrImAHJAhkdc8uCAGX7zzHCcLevln33EU91oQ2VseX+O8coAhxqoPFwWH73AHoNlcO0+CrCQSkb3tv4qu9995/DNApCZ3uv1S16FjBAoGAVfLd+0jl6EdG0nxisFYHW5Ta4o+nT7Geu3CVPk9ljdBDVh4xovZbXRmyb/yVHzdiz3hNbckgwCxM6ctYFU28zwYE7cwDasmrF2LlV92zkg8l9slsP0cqemm3C/YcDOSBMAPrQi8nazYPAWRIw5smw2vokV+7pjruwozWk3XVg1c=";
        k = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk53ySbQSg72yjlFy169uyLi+m6KUsASVCBP74j2uS+M5sOn/td5sZHwPfE2wCmXkfACNzLcLnsfa/LCy0RQv9NEIP4FK7yk2BWTF2RX2aTQfZF1GwrALJ8aK+Ae0T49oZhhOUupQZzppJJqE3af9YBfCunP6Rl6L4M3mw6ZpwdNzinE1dgLHUuAO6rgWHbmBxsWbKGckXYhTs61P6Lq/6ZhqD2l9z+rGUXFqPrgYNotG6PocJFA4oLqHAx75vrkNfpWl3h1byOay18UagjAMDTFggdpD5mIALDltYivRuf4jVDMkCYFkjui7V3RuLMeow/b5tolJv0ihTT4+fH78RwIDAQAB";
        String result = encryptByPublicKey("admin", k);
        result = "gwPHphsMxmFDIEz7ZHa9XXzdma3Wd8kZm+sAE0GGb7VUnijJi29m3YbZN8vqH2Jrav/dLUqdE6nDQe/+jRcODLw+H8BPUDa93jq2qqysr6HJEW83cHbWkQVGj8es/H+xiBvmMVgho5UOsRgq8OlTPdA8KvDHuGwai4jtDdowkn3ODDe1qTdeqVXTX4cvu9ZwGTEgqGGZ694+IJWbQbk6UiMgqEbEgOW0sisTL8ONdhn8Wej/iblYU2Ht0YUa1VjTtOP+xRjtYzUtvlk5jegU3UMD1ccSMbreVKFnQkxZ1Q3CyLH2k8JCHd2GP4le3DW7RYU7DcNiGQUGbp9De+sazg==";
        System.out.println(p);
        System.out.println(k);
        System.out.println(result);

        String s = decryptByPrivateKey(result, p);
        System.out.println(s);

    }

}
