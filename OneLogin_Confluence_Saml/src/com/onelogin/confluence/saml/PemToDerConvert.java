package com.onelogin.confluence.saml;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.apache.commons.codec.binary.Base64;

public class PemToDerConvert {
	public static PublicKey getFromString(String keystr) throws Exception
	{
	   //String S1= asciiToHex(keystr);
	   // byte[] keyBytes = new sun.misc.BASE64Decoder().decodeBuffer(keystr);
	   // byte[] keyBytes = new Base64Encoder().decodeBuffer(keystr);
	   
		Base64 base64 = new Base64();
		byte [] keyBytes = base64.decode(keystr);
		ASN1InputStream in = new ASN1InputStream (keyBytes);
		DERObject obj = in.readObject();
		RSAPublicKeyStructure pStruct = RSAPublicKeyStructure.getInstance(obj);
		RSAPublicKeySpec spec = new RSAPublicKeySpec(pStruct.getModulus(), pStruct.getPublicExponent());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}	
}
