package com.onelogin.jira.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.cxf.staxutils.StaxUtils;

import com.onelogin.AccountSettings;
import com.onelogin.AppSettings;
import com.onelogin.saml.AuthRequest;

public class AuthRequestAtlassian extends AuthRequest{

	public AuthRequestAtlassian(AppSettings appSettings, AccountSettings accountSettings) {
		super(appSettings, accountSettings);
	}

	// Required because atlassian have conflicts with XMLOutputFactory implementation
	// Avoid use specialized classes and XMLOutputFactory.newInstance()
	
	public String getRequest(int format) throws XMLStreamException, IOException {
		String result = null;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		String sBaos = "<samlp:AuthnRequest xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='"
				+ id
				+ "' Version='2.0' IssueInstant='"
				+ this.issueInstant
				+ "' ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' AssertionConsumerServiceURL='"
				+ this.appSettings.getAssertionConsumerServiceUrl()
				+ "'>"
				+ "<saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>"
				+ this.appSettings.getIssuer()
				+ "</saml:Issuer>"
				+ "<samlp:NameIDPolicy Format='urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified' AllowCreate='true'>"
				+ "</samlp:NameIDPolicy>"
				+ "<samlp:RequestedAuthnContext Comparison='exact'>"
				+ "</samlp:RequestedAuthnContext>"
				+ "<saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
				+ "</samlp:AuthnRequest>";

		// System.out.println("sBaos : " +sBaos);
		baos.write(sBaos.getBytes());
		if (format == base64) {
			result = encodeSAMLRequest(baos.toByteArray());
		}
		return result;
	}

}