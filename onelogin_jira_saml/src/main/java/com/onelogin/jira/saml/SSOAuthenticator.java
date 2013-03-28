package com.onelogin.jira.saml;

import com.atlassian.crowd.embedded.api.User;
import com.atlassian.jira.user.UserUtils;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.opensymphony.user.EntityNotFoundException;
import com.opensymphony.user.UserManager;
import java.net.URLEncoder;
import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;

public class SSOAuthenticator extends DefaultAuthenticator {

    private static final Logger log = Logger.getLogger(SSOAuthenticator.class);
    public String reqString = "";

    public SSOAuthenticator() {
    }

    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

        Principal user = null;
        XmlUtil xm = null;
        String certificateS = "";
        String setAssertionConsumerServiceUrl = "";
        String setIssuer = "";
        String setIdpSsoTargetUrl = "";
        String sFile = "jira_onelogin.xml";
        String sSAMLResponse = request.getParameter("SAMLResponse");

        try {
            if (request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null) {
                log.info("Session found; user already logged in");
                user = (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
            } else {
                xm = new XmlUtil();
                String sConf = xm.getConfigs(sFile);
                String[] sConfTemp = sConf.split("\\|");
                certificateS = sConfTemp[0];
                setAssertionConsumerServiceUrl = sConfTemp[1];
                setIssuer = sConfTemp[2];
                setIdpSsoTargetUrl = sConfTemp[3];

                if (sSAMLResponse != null) {
                    // User account specific settings. Import the certificate here
                    AccountSettings accountSettings = new AccountSettings();
                    accountSettings.setCertificate(certificateS);

                    Response samlResponse = new Response(accountSettings);
                    samlResponse.loadXmlFromBase64(request.getParameter("SAMLResponse"));

                    if (samlResponse.isValid()) {
                        // The signature of the SAML Response is valid. The source is trusted
                        final String nameId = samlResponse.getNameId();

                        user = getUser(nameId);
                        
                        String principalName = null;
                        if(user!=null)
                            principalName = user.getName();
                        
                        putPrincipalInSessionContext(request, user);
                        
                        if(principalName!=null)
                            getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, principalName);

                        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
                        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
                        
                        if(user!=null)
                            response.sendRedirect("/secure/Dashboard.jspa");

                    } else {
                        log.error("SAML Response is not valid");
                    }
                } else {
                    // The appSettings object contain application specific settings used by the SAML library
                    AppSettings appSettings = new AppSettings();

                    // Set the URL of the consume.jsp (or similar) file for this application. The SAML Response will be posted to this URL
                    appSettings.setAssertionConsumerServiceUrl(setAssertionConsumerServiceUrl);

                    // Set the issuer of the authentication request. This would usually be the URL of the issuing web application
                    appSettings.setIssuer(setIssuer);

                    // The accSettings object contains settings specific to the users account. At this point, your application must have identified the users origin
                    AccountSettings accSettings = new AccountSettings();

                    // The URL at the Identity Provider where the authentication request should be sent
                    accSettings.setIdpSsoTargetUrl(setIdpSsoTargetUrl);

                    // Generate an AuthRequest and send it to the identity provider
                    AuthRequest authReq = new AuthRequest(appSettings, accSettings);

                    reqString = accSettings.getIdp_sso_target_url()
                            + "?SAMLRequest="
                            + AuthRequest.getRidOfCRLF(URLEncoder.encode(
                            authReq.getRequest(AuthRequest.base64),
                            "UTF-8"));

                    request.getSession().setAttribute("reqString", reqString);
                }
            }
        } catch (Exception e) {
            log.error("error while trying to send the saml auth request:" + e);
        }

        return user;
    }

    @Override
    protected Principal getUser(String username) {
        /*
         * exception thrown on version 4.4.4
         * com.atlassian.crowd.embedded.ofbiz.OfBizUser cannot be cast to
         * com.opensymphony.user.User 
         * 
         * the principal returned should be of type
         * com.opensymphony.user.User
         */

        User user = UserUtils.getUser(username);
        user = (user != null) ? user : UserUtils.getUserByEmail(username);
        if (user == null) {
            log.error("username: " + username + "could not be found!!");
            return null;
        }

        com.opensymphony.user.User symphonyUser = null;
        UserManager userManager = new com.opensymphony.user.UserManager();
        try {
            symphonyUser = userManager.getUser(user.getName());
        } catch (EntityNotFoundException ex) {
            log.error("could not retrieve opensymphony user, entity was not found");
        }

        return symphonyUser;
    }

    @Override
    protected boolean authenticate(Principal prncpl, String string) throws AuthenticatorException {
        return false;
    }
}