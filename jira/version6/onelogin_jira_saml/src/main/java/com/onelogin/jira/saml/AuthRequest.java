package com.onelogin.jira.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.xml.stream.XMLStreamException;

import org.apache.commons.codec.binary.Base64;

public class AuthRequest {

	private final String id;
	private final String issueInstant;
	private final AppSettings appSettings;
	public static final int base64 = 1;

	public AuthRequest(AppSettings appSettings, AccountSettings accountSettings){
		this.appSettings = appSettings;
		id="_"+UUID.randomUUID().toString();
		SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'H:mm:ss'Z'");
		issueInstant = simpleDf.format(new Date());
	}

	public String getRequest(int format) throws XMLStreamException, IOException {
		String result = null;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		/*XMLOutputFactory factory = XMLOutputFactory.newInstance();
		XMLStreamWriter writer = factory.createXMLStreamWriter(baos);

		writer.writeStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeNamespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("ID", id);
		writer.writeAttribute("Version", "2.0");
		writer.writeAttribute("IssueInstant", this.issueInstant);
		writer.writeAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		writer.writeAttribute("AssertionConsumerServiceURL", this.appSettings.getAssertionConsumerServiceUrl());

		writer.writeStartElement("saml","Issuer","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(this.appSettings.getIssuer());
		writer.writeEndElement();

		writer.writeStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
		writer.writeAttribute("AllowCreate", "true");
		writer.writeEndElement();

		writer.writeStartElement("samlp","RequestedAuthnContext","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("Comparison", "exact");

		writer.writeStartElement("saml","AuthnContextClassRef","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		writer.writeEndElement();

		writer.writeEndElement();
		writer.writeEndElement();
		writer.flush();*/
		
		String sBaos = "<samlp:AuthnRequest xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='" + id + "' Version='2.0' IssueInstant='" + this.issueInstant + "' ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' AssertionConsumerServiceURL='" + this.appSettings.getAssertionConsumerServiceUrl() + "'>"
				+ "<saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>" + this.appSettings.getIssuer() + "</saml:Issuer>"
				+ "<samlp:NameIDPolicy Format='urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified' AllowCreate='true'>"
				+ "</samlp:NameIDPolicy>"
				+ "<samlp:RequestedAuthnContext Comparison='exact'>"
				+ "</samlp:RequestedAuthnContext>"
				+ "<saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
				+ "</samlp:AuthnRequest>";

		//System.out.println("sBaos : " +sBaos);
		baos.write(sBaos.getBytes());
		if (format == base64) {       
			result = encodeSAMLRequest(baos.toByteArray());
		}
		return result;
	}

	private String encodeSAMLRequest(byte[] pSAMLRequest) throws RuntimeException {

		Base64 base64Encoder = new Base64();

		try {
			ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
			Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);

			DeflaterOutputStream def = new DeflaterOutputStream(byteArray, deflater);
			def.write(pSAMLRequest);
			def.close();
			byteArray.close();

			String stream = new String(base64Encoder.encode(byteArray.toByteArray()));

			return stream.trim();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public String getSSOurl(String IdpSsoTargetUrl, String... parameters) throws XMLStreamException, UnsupportedEncodingException, IOException
	{
		String ssourl = IdpSsoTargetUrl+"?SAMLRequest=" + URLEncoder.encode(getRequest(base64),"UTF-8");
		
		if(parameters != null){
			String relayState = parameters.length > 0 ? parameters[0] : "";
			if(relayState != null && !relayState.isEmpty()){
				ssourl = ssourl + "&RelayState=" + relayState;
			}
		}
		return ssourl;
	}
}