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

	public String getRequest(int format) throws XMLStreamException, IOException {
		String result = "";

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		XMLStreamWriter writer = StaxUtils.createXMLStreamWriter(baos);

		writer.writeStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeNamespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("ID", super.id);
		writer.writeAttribute("Version", "2.0");
		writer.writeAttribute("IssueInstant", super.issueInstant);
		writer.writeAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		writer.writeAttribute("AssertionConsumerServiceURL", super.appSettings.getAssertionConsumerServiceUrl());

		writer.writeStartElement("saml","Issuer","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(super.appSettings.getIssuer());
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
		writer.flush();
                
		result = encodeSAMLRequest(baos.toByteArray());
		return result;
	}

}