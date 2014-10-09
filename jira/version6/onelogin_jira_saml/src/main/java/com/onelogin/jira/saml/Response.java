package com.onelogin.jira.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class Response {

	private Document xmlDoc;
	private NodeList assertions;
	private Element rootElement;
	private final AccountSettings accountSettings;
	private final Certificate certificate;
	private String currentUrl;

	public Response(AccountSettings accountSettings) throws CertificateException {
		this.accountSettings = accountSettings;
		certificate = new Certificate();
		certificate.loadCertificate(this.accountSettings.getCertificate());
	}

	public void loadXml(String xml) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
		DocumentBuilderFactory fty = DocumentBuilderFactory.newInstance();
		fty.setNamespaceAware(true);
		DocumentBuilder builder = fty.newDocumentBuilder();
		ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes());
		xmlDoc = builder.parse(bais);
		// Loop through the doc and tag every element with an ID attribute as an XML ID node.
 		XPath xpath = XPathFactory.newInstance().newXPath();
 		XPathExpression expr = xpath.compile("//*[@ID]");
 		NodeList nodeList = (NodeList) expr.evaluate(xmlDoc, XPathConstants.NODESET);
 		for (int i=0; i<nodeList.getLength() ; i++) {
 			Element elem = (Element) nodeList.item(i);
 			Attr attr = (Attr) elem.getAttributes().getNamedItem("ID");
 			elem.setIdAttributeNode(attr, true);
 		}
	}


	public void loadXmlFromBase64(String response) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
		Base64 base64 = new Base64();
		byte[] decodedB = base64.decode(response);
		String decodedS = new String(decodedB);
		loadXml(decodedS);
	}

	public boolean isValid() throws Exception {
		NodeList nodes = xmlDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

		if(nodes==null || nodes.getLength()==0){
			System.out.println("Can't find signature in document.");
			throw new Exception("Can't find signature in document.");
		}else{
			System.out.println("nodes " +nodes.getLength());
		}

		X509Certificate cert = certificate.getX509Cert();		
		DOMValidateContext ctx = new DOMValidateContext(cert.getPublicKey() , nodes.item(0));				
		XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");
		XMLSignature xmlSignature = sigF.unmarshalXMLSignature(ctx);


        if (!isAllowedDate()){
        	return false;
        }
                
		return xmlSignature.validate(ctx);
	}

	public String getNameId() throws Exception {
		NodeList nodes = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");	
		if(nodes.getLength()==0){
			throw new Exception("No name id found in document");
		}
		return nodes.item(0).getTextContent();
	}
        
        
        public String getIssuer() throws Exception {
		NodeList nodes = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");		

		if(nodes.getLength()==0){
			throw new Exception("No issuer found in document");
		}

		return nodes.item(0).getTextContent();
	}
        
        public boolean isAllowedDate() throws Exception {
            NodeList confirmationData = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Conditions");
            if(confirmationData.getLength()==0){
			throw new Exception("No conditions were found in document");
		}
        
            DateFormat m_ISO8601Local = new SimpleDateFormat ("yyyy-MM-dd'T'HH:mm:ss'Z'");
            m_ISO8601Local.setTimeZone(TimeZone.getTimeZone("UTC"));

            Date now = new Date();
            Date notBeforeTime = m_ISO8601Local.parse(confirmationData.item(0).
                                                           getAttributes().
                                                           getNamedItem("NotBefore").
                                                           getNodeValue());
            
            Date notOnOrAfterTime = m_ISO8601Local.parse(confirmationData.item(0).
                                                           getAttributes().
                                                           getNamedItem("NotOnOrAfter").
                                                           getNodeValue());
                    
            return (now.after(notBeforeTime) && now.before(notOnOrAfterTime));
        }
        
        public void setDestinationUrl(String urld){
    		currentUrl = urld;
    	}
        
}