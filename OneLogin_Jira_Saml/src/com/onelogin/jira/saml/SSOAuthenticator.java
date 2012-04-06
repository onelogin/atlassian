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

	public Principal getUser(HttpServletRequest request,HttpServletResponse response) {

		// System.out.println("1: ");
		Principal user = null;

		String sSAMLResponse = request.getParameter("SAMLResponse");
		
		try {
			if(request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null)
			{
				log.info("Session found; user already logged in");
				user = (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
			}
			else
			{
				if (sSAMLResponse != null) {
					// System.out.println("2: ");

					// final String remoteIP = request.getRemoteAddr();
					// final String remoteHost = request.getRemoteHost();

					String certificateS = "MIICMTCCAiWgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD"
							+ "YWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxv"
							+ "Z2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEyMDIyMDE4NDkxMloX"
							+ "DTE3MDIxOTE4NDkxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju"
							+ "aWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAX"
							+ "BgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw"
							+ "ggEKAoIBAQDRX0RLd3fFYKD0AjivDn1PfkeEJNZIpBsMJQC+ukSNi8yx1uSO6w3S"
							+ "VVMO4Y/3//rYqsAmrAPG95hRCUZfk0oO1t05TDr3LN4z3CA0RA4Uqy7/V7jYYQH7"
							+ "2yiMheaY9+R5I2lYD14ALzSgvebve4n09DLf+dnmJfH6anyCzRZR4P5L0rnBcllb"
							+ "veC1vaSXgFQROrODvbpG2FI7+qJwocuNjffTRXKMTGbN+vQywgg4WrnukUGdMWL8"
							+ "rb2qlPukWMP6fqHTrgM5yevfWn0Gs9VaQupeiuMGo7dLnaUfJIm6mbcHCO5swuZP"
							+ "kJQ2P9xJKHB2c4BNi0q9C8mPhUfVmsLdAgMBAAEwAwYBAAMBAA==";

					// User account specific settings. Import the certificate here
					AccountSettings accountSettings = new AccountSettings();
					accountSettings.setCertificate(certificateS);

					Response samlResponse = new Response(accountSettings);
					samlResponse.loadXmlFromBase64(request
							.getParameter("SAMLResponse"));

					if (samlResponse.isValid()) {
						// System.out.println("3: ");

						// The signature of the SAML Response is valid. The source
						// is trusted
						final String nameId = samlResponse.getNameId();

						user = getUser(nameId);

						// System.out.println("3-1: ");

						putPrincipalInSessionContext(request, user);
						getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, nameId);

						// System.out.println("3-2: ");

						request.getSession().setAttribute(
								DefaultAuthenticator.LOGGED_IN_KEY, user);
						request.getSession().setAttribute(
								DefaultAuthenticator.LOGGED_OUT_KEY, null);
					} else {
						// System.out.println("4: SAML Response is not valid");
					}
				}
				else
				{
					// System.out.println("6: ");
					
					// The appSettings object contain application specific settings
					// used by the SAML library
					AppSettings appSettings = new AppSettings();

					// Set the URL of the consume.jsp (or similar) file for this
					// app. The SAML Response will be posted to this URL
					// appSettings.setAssertionConsumerServiceUrl("http://localhost:8090/oneloginconsume.jsp");
					appSettings
					.setAssertionConsumerServiceUrl("http://localhost:8080/login.jsp");

					// Set the issuer of the authentication request. This would
					// usually be the URL of the issuing web application
					// appSettings.setIssuer("https://www.mywebapp.com");
					appSettings.setIssuer("http://localhost:8080/secure/Dashboard.jspa");

					// The accSettings object contains settings specific to the
					// users account. At this point, your application must have
					// identified the users origin
					AccountSettings accSettings = new AccountSettings();

					// The URL at the Identity Provider where the authentication
					// request should be sent
					accSettings
					.setIdpSsoTargetUrl("https://app.onelogin.com/saml/signon/39854");

					// Generate an AuthRequest and send it to the identity provider
					AuthRequest authReq = new AuthRequest(appSettings, accSettings);
					
					reqString = accSettings.getIdp_sso_target_url()
							+ "?SAMLRequest="
							+ AuthRequest.getRidOfCRLF(URLEncoder.encode(
									authReq.getRequest(AuthRequest.base64),
									"UTF-8"));								
					
					// System.out.println("7: " + reqString);

					request.getSession().setAttribute("reqString", reqString);
				}
			}
		} catch (Exception e) {
			System.out.println("8: " + e.getMessage());
		}
		
		return user;
	}
}
