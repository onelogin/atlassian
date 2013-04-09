package com.onelogin.confluence.saml;

import com.atlassian.confluence.event.events.security.LoginEvent;
import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.auth.LoginReason;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

public class SSOAuthenticator extends ConfluenceAuthenticator {

    private static final Logger log = Logger.getLogger(SSOAuthenticator.class);
    public String reqString = "";

    public SSOAuthenticator() {
    }

    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

        Principal user = null;
        HashMap<String, String> configValues = getConfigurationValues("conf_onelogin.xml");
        String sSAMLResponse = request.getParameter("SAMLResponse");

        try {

            if (sSAMLResponse != null) {

               request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY,  null);
               request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
                
                final String remoteIP = request.getRemoteAddr();
                final String remoteHost = request.getRemoteHost();


                   Response samlResponse = getSamlResponse(configValues.get("certificate"),request.getParameter("SAMLResponse"));

                if (samlResponse.isValid()) {
                    // The signature of the SAML Response is valid. The source is trusted
                    String sNameId = samlResponse.getNameId();
                    user = getUser(sNameId);

                    putPrincipalInSessionContext(request, user);
                    
                    if(user!=null)
                        getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, sNameId);

                    // Firing this event is necessary to ensure the user's personal information is initialized correctly.
                    getEventPublisher().publish(new LoginEvent(this, sNameId, request.getSession().getId(), remoteHost, remoteIP));
                    LoginReason.OK.stampRequestResponse(request, response);

                    request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
                    request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);

                    
                    if(user!=null && !response.isCommitted())
                            response.sendRedirect("/dashboard.action");                            
                    
                } else {
                    log.error("SAML Response is not valid");
                }
            } else if (request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null) {
                log.info("Session found; user already logged in");
                user = (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
            } else {

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

                reqString = accSettings.getIdp_sso_target_url()
                        + "?SAMLRequest="
                        + AuthRequest.getRidOfCRLF(URLEncoder.encode(
                        authReq.getRequest(AuthRequest.base64),
                        "UTF-8"));

                request.getSession().setAttribute("reqString", reqString);
            }

        } catch (Exception e) {
            log.error("error while trying to send the saml auth request:" + e);
        }

        return user;
    }

    private HashMap<String, String> getConfigurationValues(String file) {
        XmlUtil xm = new XmlUtil();
        HashMap<String, String> configValues = new HashMap<String, String>();
        String sConf = xm.getConfigs(file);
        String[] sConfTemp = sConf.split("\\|");
        configValues.put("certificate", sConfTemp[0]);
        configValues.put("assertionConsumerServiceUrl", sConfTemp[1]);
        configValues.put("issuer", sConfTemp[2]);
        configValues.put("idpSsoTargetUrl", sConfTemp[3]);
        return configValues;
    }

    private Response getSamlResponse(String certificate,String responseEncrypted) throws CertificateException, ParserConfigurationException, SAXException, IOException {
        // User account specific settings. Import the certificate here
        AccountSettings accountSettings = new AccountSettings();
        accountSettings.setCertificate(certificate);

        Response samlResponse = new Response(accountSettings);
        samlResponse.loadXmlFromBase64(responseEncrypted);
        return samlResponse;
    }


    @Override
    protected boolean authenticate(Principal prncpl, String string) throws AuthenticatorException {
        return false;
    }
    
}