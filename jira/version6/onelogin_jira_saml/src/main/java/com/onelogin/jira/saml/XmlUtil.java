package com.onelogin.jira.saml;

import java.io.File;
import java.util.HashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

public class XmlUtil {
    public XmlUtil() {
    }

    public static void main(String[] argv) {
         //XmlUtil xm = new XmlUtil();
         //String sFile = "c:\\temp\\jira_onelogin.xml";
//    	 String sFile = "/Users/jenn/atlassian/jira/jira_onelogin.xml";
//    	HashMap<String,String> configValues = new HashMap<String,String>();
//        String sConf = xm.getConfigs(sFile);
//        String[] sConfTemp = sConf.split("\\|");
//        configValues.put("certificate", sConfTemp[0]);
//        configValues.put("assertionConsumerServiceUrl", sConfTemp[1]);
//        configValues.put("issuer", sConfTemp[2]);
//        configValues.put("idpSsoTargetUrl", sConfTemp[3]);
//        System.out.println(configValues.size());
    }

    public String getConfigs(String sFile) {
        String strResult = "";
        
		try
		{
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            Document doc = docBuilder.parse (new File(sFile));
            doc.getDocumentElement ().normalize ();
            NodeList listOfUser = doc.getElementsByTagName("config");
            
            for(int s=0; s<listOfUser.getLength() ; s++)
            {
                Node systemNode = listOfUser.item(s);
                
                if(systemNode.getNodeType() == Node.ELEMENT_NODE)
                {
                    Element systemElement = (Element)systemNode;
                    
                    // Certificate
                    NodeList userIdList = systemElement.getElementsByTagName("certificate");
                    Node userIdNode = userIdList.item(0);
                    Element userIdElement = (Element)userIdNode;
                    if(userIdElement != null)
                    {
	                    if(userIdElement.getChildNodes().item(0) != null)
	                    {
	                    	strResult = userIdElement.getChildNodes().item(0).getNodeValue().trim() + "|";
	                    }
                    }

                    // Assertion
                    NodeList firstNameList = systemElement.getElementsByTagName("assertion");
                    Node firstNameNode = firstNameList.item(0);
                    Element firstNameElement = (Element)firstNameNode;
                    if(firstNameElement != null)
                    {
	                    if(firstNameElement.getChildNodes().item(0) != null)
	                    {
	                    	strResult += firstNameElement.getChildNodes().item(0).getNodeValue().trim() + "|";
	                    }
                    }

                    // Issuer
                    NodeList lastNameList = systemElement.getElementsByTagName("issuer");
                    Node lastNameNode = lastNameList.item(0);
                    Element lastNameElement = (Element)lastNameNode;
                    if(lastNameElement != null)
                    {
	                    if(lastNameElement.getChildNodes().item(0) != null)
	                    {
	                    	strResult += lastNameElement.getChildNodes().item(0).getNodeValue().trim() + "|";
	                    }
                    }
                    
                    // SSOTarget
                    NodeList emailList = systemElement.getElementsByTagName("ssotarget");
                    Node emailNode = emailList.item(0);
                    Element emailElement = (Element)emailNode;
                    if(emailElement != null)
                    {
	                    if(emailElement.getChildNodes().item(0) != null)
	                    {
	                    	strResult += emailElement.getChildNodes().item(0).getNodeValue().trim();
	                    }
                    }
                }
            }
        } catch (SAXParseException err) {
            System.out.println("** Parsing error" + ", line " + err.getLineNumber() + ", uri " + err.getSystemId());
            System.out.println(" " + err.getMessage());
        } catch (SAXException e) {
            Exception x = e.getException();
            ((x == null) ? e : x).printStackTrace();
        } catch (Throwable t) {
            t.printStackTrace();
        }
        return strResult;
    }
}