package com.qcloud.kms;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class KMSTool {
	private static char[] b64c = new char[] { 'A', 'B', 'C', 'D',
			'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
			'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
			'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
			'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
			'4', '5', '6', '7', '8', '9', '+', '/' };
	private static String base64Code= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
    private static final String CONTENT_CHARSET = "UTF-8";

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

	
	public static String base64_encode(byte[] data) {
		StringBuffer sb = new StringBuffer();
		int len = data.length;
		int i = 0;
		int b1, b2, b3;
		while (i < len) {
			b1 = data[i++] & 0xff;
			if (i == len) {
				sb.append(b64c[b1 >>> 2]);
				sb.append(b64c[(b1 & 0x3) << 4]);
				sb.append("==");
				break;
			}
			b2 = data[i++] & 0xff;
			if (i == len) {
				sb.append(b64c[b1 >>> 2]);
				sb.append(b64c[((b1 & 0x03) << 4)
						| ((b2 & 0xf0) >>> 4)]);
				sb.append(b64c[(b2 & 0x0f) << 2]);
				sb.append("=");
				break;
			}
			b3 = data[i++] & 0xff;
			sb.append(b64c[b1 >>> 2]);
			sb.append(b64c[((b1 & 0x03) << 4)
					| ((b2 & 0xf0) >>> 4)]);
			sb.append(b64c[((b2 & 0x0f) << 2)
					| ((b3 & 0xc0) >>> 6)]);
			sb.append(b64c[b3 & 0x3f]);
		}
		return sb.toString();
	}
	
	
	public static String base64_encode(String srcStr) {  
        return base64_encode(srcStr.getBytes());
    }  
	
	public static String base64_decode(String srcStr) {  

        if(srcStr == null || srcStr.length() == 0) {  
            return srcStr;  
        }  

        int eqCounter= 0;  
        if(srcStr.endsWith("==")) {  
            eqCounter= 2;  
        } else if(srcStr.endsWith("=")) {  
            eqCounter= 1;  
        }  
        srcStr= srcStr.replaceAll("=", "");  
        srcStr= srcStr.replaceAll("\r\n", "");  
  
        char[] srcStrCh= srcStr.toCharArray();  
        StringBuilder indexBinStr= new StringBuilder();  
        String indexBin= null;  
        for(int i= 0; i< srcStrCh.length; i++) {  
            indexBin= Integer.toBinaryString(base64Code.indexOf((int)srcStrCh[i]));  
            while(indexBin.length()< 6) {  
                indexBin= "0"+ indexBin;  
            }  
            indexBinStr.append(indexBin);  
        }  

        if(eqCounter == 1) {  
            indexBinStr.delete(indexBinStr.length()- 2, indexBinStr.length());  
        } else if(eqCounter == 2) {  
            indexBinStr.delete(indexBinStr.length()- 4, indexBinStr.length());  
        }  
        String asciiBinStr= String.valueOf(indexBinStr);  

        String asciiBin= null;  
        char[] ascii= new char[asciiBinStr.length()/ 8];  
        for(int i= 0; i< ascii.length; i++) {  
            asciiBin= asciiBinStr.substring(0, 8);  
            asciiBinStr= asciiBinStr.substring(8);  
            ascii[i]= (char)Integer.parseInt(asciiBin, 2);  
        }  
        return String.valueOf(ascii);  
    }  
	
	public static String sign(String src, String key,String method)
    		throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException 
    {
		Mac mac ; 
		if( method == "sha1")
		{
           mac = Mac.getInstance(HMAC_ALGORITHM);
		}
		else
		{
			mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
		}
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(CONTENT_CHARSET), mac.getAlgorithm());
        mac.init(secretKey);
        byte[] digest = mac.doFinal(src.getBytes(CONTENT_CHARSET));
        
        return new String(base64_encode(digest));
    }
}
