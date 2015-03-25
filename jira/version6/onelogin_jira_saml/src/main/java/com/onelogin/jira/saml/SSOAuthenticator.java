package com.onelogin.jira.saml;

import com.atlassian.crowd.embedded.api.User;
import com.atlassian.jira.user.UserUtils;
import com.atlassian.jira.util.UrlValidator;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

public class SSOAuthenticator extends DefaultAuthenticator {

    /**
	 * 
	 */
	private static final long serialVersionUID = -7616435144078769382L;
	
	private static final Logger log = Logger.getLogger(SSOAuthenticator.class);
	
    public String reqString = "/";

    public SSOAuthenticator() {
    }

    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
    	//System.out.println(" getUser ");
    	
        Principal user = null;
        
        if (request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null) {
            log.info("Session found; user already logged in");
            user = (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
            log.info(" user :" + user);
         }else{
        	 
	        HashMap<String,String> configValues = getConfigurationValues("jira_onelogin.xml");
	        log.info(" configValues loaded issuer:" + configValues.get("issuer"));
	        
	        String os_destination = request.getParameter("os_destination");
	        if(os_destination != null){
	        	request.getSession().setAttribute("os_destination", os_destination);
	        }
        
	        String sSAMLResponse = request.getParameter("SAMLResponse");
	        log.info("get SAMLResponse");
        	//System.out.println("get SAMLResponse");
        
	        try {
	        	if (sSAMLResponse == null) {
		        
	                    // The appSettings object contain application specific settings used by the SAML library
	                    AppSettings appSettings = new AppSettings();
	                    
	                    // Set the URL of the consume.jsp (or similar) file for this application. The SAML Response will be posted to this URL
	                    appSettings.setAssertionConsumerServiceUrl(configValues.get("assertionConsumerServiceUrl"));

	                    // Set the issuer of the authentication request. This would usually be the URL of the issuing web application
	                    appSettings.setIssuer(configValues.get("issuer"));

	                    // The accSettings object contains settings specific to the users account. At this point, your application must have identified the users origin
	                    AccountSettings accSettings = new AccountSettings();

	                    // The URL at the Identity Provider where the authentication request should be sent
	                    accSettings.setIdpSsoTargetUrl(configValues.get("idpSsoTargetUrl"));

	                    // Generate an AuthRequest and send it to the identity provider
	                    AuthRequest authReq = new AuthRequest(appSettings, accSettings);
	                    log.info("Generated AuthRequest and send it to the identity provider ");
	                    //System.out.println("Generated AuthRequest and send it to the identity provider ");

	                    String relayState = null;
	                    if(os_destination != null){
	                    	relayState = request.getRequestURL().toString().replace(request.getRequestURI(), os_destination);
	                    }
	                    reqString = authReq.getSSOurl(accSettings.getIdp_sso_target_url(), relayState);   			
	                   
	                
	        	} else {
	
	                    request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY,  null);
	                    request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
	                    
	                    // User account specific settings. Import the certificate here
	                    Response samlResponse = getSamlResponse(configValues.get("certificate"),request.getParameter("SAMLResponse"));                    
	
	                    if (samlResponse.isValid()) {
	                        // The signature of the SAML Response is valid. The source is trusted
	                        final String nameId = samlResponse.getNameId();
	                        user = getUser(nameId);
	                        log.debug(" SAML user :" + user);
	                        
	                        if(user!=null){
	                            putPrincipalInSessionContext(request, user);
	                            getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, nameId);
	                            request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
	                            request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
	
	                            String relayState = request.getParameter("RelayState").toString();
	                            
	                            if(relayState != null && UrlValidator.isValid(relayState) ){
	                                if(relayState.contains(request.getServerName())){
	                                    //System.out.println("valid RelayState ");
	                                    request.getSession().setAttribute("os_destination",relayState);
	                                }                           
	                            }
	
	                        }else{
	                            getElevatedSecurityGuard().onFailedLoginAttempt(request, nameId);
	                        }
	                           
	                    } else {
	                        log.error("SAML Response is not valid");
	                    }
                	} 
     
	        } catch (Exception e) {
	        	log.error("error while trying to send the saml auth request:" + e);
	        }
         }
        log.debug("reqString : " +reqString );
        request.getSession().setAttribute("reqString", reqString);
        return user;
    }

    private Response getSamlResponse(String certificate,String responseEncrypted) throws CertificateException, ParserConfigurationException, SAXException, IOException, XPathExpressionException {
    	AccountSettings accountSettings = new AccountSettings();
        accountSettings.setCertificate(certificate);

        Response samlResponse = new Response(accountSettings);
        samlResponse.loadXmlFromBase64(responseEncrypted);
        log.debug("samlResponse" + samlResponse.toString());
        return samlResponse;
    }

    private HashMap<String, String> getConfigurationValues(String file) {
        XmlUtil xm = new XmlUtil();
        HashMap<String,String> configValues = new HashMap<String,String>();
        String sConf = xm.getConfigs(file);
        String[] sConfTemp = sConf.split("\\|");
        configValues.put("certificate", sConfTemp[0]);
        configValues.put("assertionConsumerServiceUrl", sConfTemp[1]);
        configValues.put("issuer", sConfTemp[2]);
        configValues.put("idpSsoTargetUrl", sConfTemp[3]);
        return configValues;
    }
    
    
    
    @Override
    protected Principal getUser(String username) {
        User user = UserUtils.getUser(username);
        return user;
    }

    @Override
    protected boolean authenticate(Principal prncpl, String string) throws AuthenticatorException {
    	log.info("authenticate");
        return false;
    }
}