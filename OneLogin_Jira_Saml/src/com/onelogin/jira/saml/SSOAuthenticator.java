package com.onelogin.jira.saml;

import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import java.security.Principal;
import javax.servlet.http.*;
import org.apache.log4j.Category;
import java.net.URLEncoder;

public class SSOAuthenticator extends JiraSeraphAuthenticator {
	private static final Category log = Category.getInstance(SSOAuthenticator.class);
	public String reqString = "";
	
	public SSOAuthenticator(){}

	public Principal getUser(HttpServletRequest request,HttpServletResponse response)
	{
		Principal user = null;
		XmlUtil xm = null;
		String certificateS = "";
		String setAssertionConsumerServiceUrl = "";
		String setIssuer = "";
		String setIdpSsoTargetUrl = "";
		String sFile = "jira_onelogin.xml";
		String sSAMLResponse = request.getParameter("SAMLResponse");
		
		try
		{
			if(request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null)
			{
				log.info("Session found; user already logged in");
				user = (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
			}
			else
			{
				xm = new XmlUtil();
				String sConf = xm.getConfigs(sFile);
				String[] sConfTemp = sConf.split("\\|");
				certificateS = sConfTemp[0];
				setAssertionConsumerServiceUrl = sConfTemp[1];
				setIssuer = sConfTemp[2];
				setIdpSsoTargetUrl = sConfTemp[3];
				
				if (sSAMLResponse != null)
				{
					// User account specific settings. Import the certificate here
					AccountSettings accountSettings = new AccountSettings();
					accountSettings.setCertificate(certificateS);

					Response samlResponse = new Response(accountSettings);
					samlResponse.loadXmlFromBase64(request.getParameter("SAMLResponse"));

					if (samlResponse.isValid())
					{
						// The signature of the SAML Response is valid. The source is trusted
						final String nameId = samlResponse.getNameId();

						user = getUser(nameId);

						putPrincipalInSessionContext(request, user);
						getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, nameId);

						request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
						request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
					}
					else
					{
						System.out.println("SAML Response is not valid");
					}
				}
				else
				{
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
			System.out.println("8: " + e.getMessage());
		}
		
		return user;
	}
}