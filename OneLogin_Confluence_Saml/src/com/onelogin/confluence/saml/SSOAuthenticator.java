package com.onelogin.confluence.saml;

import com.atlassian.confluence.event.events.security.LoginEvent;
import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.actions.LoginAction;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.auth.LoginReason;
import com.atlassian.seraph.filter.SecurityFilter;
import com.atlassian.seraph.util.RedirectUtils;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import javax.servlet.http.*;
import org.apache.log4j.Category;
import com.atlassian.user.User;
import com.opensymphony.xwork.ActionSupport;
import com.atlassian.confluence.core.ConfluenceActionSupport;

public class SSOAuthenticator extends ConfluenceAuthenticator  {
	private static final Category log = Category
			.getInstance(SSOAuthenticator.class);
	public String reqString = "";

	public SSOAuthenticator() {
	}

	public Principal getUser(HttpServletRequest request,HttpServletResponse response){

		Principal user = null;
		LoginAction la = null;
		XmlUtil xm = null;
		boolean valid = false;
		String sRelayStateBack = "";
		String sNameId = "";
		String certificateS = "";
		String setAssertionConsumerServiceUrl = "";
		String setIssuer = "";
		String setIdpSsoTargetUrl = "";
		String sFile = "conf_onelogin.xml";
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
					final String remoteIP = request.getRemoteAddr();
					final String remoteHost = request.getRemoteHost();
					
					// User account specific settings. Import the certificate here
					AccountSettings accountSettings = new AccountSettings();
					accountSettings.setCertificate(certificateS);
					
					Response samlResponse;
					samlResponse = new Response(accountSettings);
					samlResponse.loadXmlFromBase64(request.getParameter("SAMLResponse"));
					valid = samlResponse.isValid();
					sNameId = samlResponse.getNameId();
					
					if (valid)
					{
						// The signature of the SAML Response is valid. The source is trusted
						final String nameId = sNameId;

						user = new User()
						{
							public String getFullName()
							{
								return nameId;
							}

							public String getEmail()
							{
								return "";
							}

							public String getName()
							{
								return nameId;
							}
						};

						putPrincipalInSessionContext(request, user);
						getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, nameId);

						// Firing this event is necessary to ensure the user's personal information is initialized correctly.
						getEventPublisher().publish(new LoginEvent(this, nameId, request.getSession().getId(), remoteHost, remoteIP));
						LoginReason.OK.stampRequestResponse(request, response);

						request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
						request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
						
						String originalURL = request.getParameter("RelayState");
						
						if(!originalURL.equals(""))
						{
							sRelayStateBack = originalURL;
							la = new LoginAction();
							la.setOs_destination(sRelayStateBack);
							response.sendRedirect(request.getContextPath() + la.getOs_destination());
						}
					}
					else
					{
						System.out.println("SAML Response is not valid");
					}
				}
				else
				{
					String originalURL1 = (String) request.getAttribute(SecurityFilter.ORIGINAL_URL);
					String sTemp = "/onelogin.jsp?os_destination=";
					originalURL1 = originalURL1.substring(sTemp.length());
					
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
									"UTF-8")) + "&RelayState=" + originalURL1;						

					request.getSession().setAttribute("reqString", reqString);
				}
			}
		} catch (Exception e) {
			System.out.println("8: " + e.getMessage());
		}

		return user;
	}
}