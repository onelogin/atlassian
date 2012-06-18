package com.onelogin.jira.saml;

import java.net.URLEncoder;

public class TstAuthRequest {
	
	public static void main(String[] argv)
	{
		try{
			String reqString = "";

			// The appSettings object contain application specific settings used by the SAML library
			AppSettings appSettings = new AppSettings();

			// Set the URL of the consume.jsp (or similar) file for this application. The SAML Response will be posted to this URL
			appSettings.setAssertionConsumerServiceUrl("http://localhost:8080/login.jsp");

			// Set the issuer of the authentication request. This would usually be the URL of the issuing web application
			appSettings.setIssuer("http://localhost:8080/secure/Dashboard.jspa");

			// The accSettings object contains settings specific to the users account. At this point, your application must have identified the users origin
			AccountSettings accSettings = new AccountSettings();

			// The URL at the Identity Provider where the authentication request should be sent
			accSettings.setIdpSsoTargetUrl("https://app.onelogin.com/saml/signon/39854");

			// Generate an AuthRequest and send it to the identity provider
			AuthRequest authReq = new AuthRequest(appSettings, accSettings);
			
			reqString = accSettings.getIdp_sso_target_url()
					+ "?SAMLRequest="
					+ AuthRequest.getRidOfCRLF(URLEncoder.encode(
							authReq.getRequest(AuthRequest.base64),
							"UTF-8"));			
		}
		catch(Exception ex)
		{
			System.out.println(ex.getMessage());
		}
	}
}
