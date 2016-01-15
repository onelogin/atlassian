package com.onelogin.jira.saml;

import java.security.Principal;
import java.util.HashMap;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.util.UrlValidator;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import com.atlassian.jira.security.groups.GroupManager;
import com.onelogin.AccountSettings;
import com.onelogin.AppSettings;
import com.onelogin.saml.Response;

public class SSOAuthenticator extends JiraSeraphAuthenticator {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7616435144078769382L;

	private static final Logger log = Logger.getLogger(SSOAuthenticator.class);

	public String reqString = "/";
 
	// Members of this JIRA group are allowed to authenticate against JIRA and bypass OneLogin.  
	private String WHITELISTED_GROUP = "onelogin-whitelist"; 
 
	public SSOAuthenticator() {
	}

	@Override
	public Principal getUser(HttpServletRequest request,
			HttpServletResponse response) {

		log.debug("getUser  ");
		Principal user = null;

		if (request.getSession() != null && 
			request.getSession().getAttribute( DefaultAuthenticator.LOGGED_IN_KEY) != null) {
			log.debug("Session found; user already logged in");
			user = (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
			log.debug(" user :" + user);
		} else {

			HashMap<String, String> configValues = getConfigurationValues("jira_onelogin.xml");
			log.debug(" configValues loaded issuer:" + configValues.get("issuer"));

			String os_destination = request.getParameter("os_destination");
			if (os_destination != null) {
				request.getSession().setAttribute("os_destination", os_destination);
			}

			String sSAMLResponse = request.getParameter("SAMLResponse");
			log.debug("get SAMLResponse  " + sSAMLResponse);

			try {
				if (sSAMLResponse == null) {
					// The appSettings object contain application specific
					// settings used by the SAML library
					AppSettings appSettings = new AppSettings();

					// Set the URL of the consume.jsp (or similar) file for this
					// application. The SAML Response will be posted to this URL
					appSettings.setAssertionConsumerServiceUrl(configValues.get("assertionConsumerServiceUrl"));

					// Set the issuer of the authentication request. This would
					// usually be the URL of the issuing web application
					appSettings.setIssuer(configValues.get("issuer"));

					// The accSettings object contains settings specific to the
					// users account. At this point, your application must have
					// identified the users origin
					AccountSettings accSettings = new AccountSettings();

					// The URL at the Identity Provider where the authentication
					// request should be sent
					accSettings.setIdpSsoTargetUrl(configValues.get("idpSsoTargetUrl"));

					// Generate an AuthRequest and send it to the identity
					// provider
					AuthRequestAtlassian authReq = new AuthRequestAtlassian(appSettings, accSettings);
					log.debug("Generated AuthRequest and send it to the identity provider ");

					String relayState = null;
					if (os_destination != null) {
						relayState = request.getRequestURL().toString().replace(request.getRequestURI(), os_destination);
					}
					reqString = authReq.getSSOurl(relayState);

					log.debug("reqString : " + reqString);

					request.getSession().setAttribute("reqString", reqString);

				} else {

					request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, null);
					request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);

					// User account specific settings. Import the certificate here
					Response samlResponse = getSamlResponse(configValues.get("certificate"),
														    request.getParameter("SAMLResponse"),
														    request.getRequestURL().toString());

					
					if (samlResponse.isValid()) {
						// The signature of the SAML Response is valid. The
						// source is trusted
						final String nameId = samlResponse.getNameId();
						user = getUser(nameId);
						log.debug(" SAML user :" + user);
						

						if (user != null) {
							putPrincipalInSessionContext(request, user);
							getElevatedSecurityGuard()
									.onSuccessfulLoginAttempt(request, nameId);
							request.getSession().setAttribute(
									DefaultAuthenticator.LOGGED_IN_KEY, user);
							request.getSession().setAttribute(
									DefaultAuthenticator.LOGGED_OUT_KEY, null);

							if (request.getParameter("RelayState") != null) {
								String relayState = request.getParameter("RelayState").toString();
								if (UrlValidator.isValid(relayState)) {
									if (relayState.contains(request
											.getServerName())) {
										request.getSession().setAttribute("os_destination", relayState);
										log.info("redirect to ->" + relayState);
										// response.sendRedirect(relayState);
									} else {
										log.error(" relayState want to redirect to different server:["
												+ relayState + "]");
									}
								} else {
									log.error(" relayState invalid:["+ relayState + "]");
								}
							} else {
								log.info(" Not relayState found redicect to home");
							}

						} else {
							getElevatedSecurityGuard().onFailedLoginAttempt(request, nameId);
						}

					} else {
						log.error("SAML Response is not valid");
					}
				}

			} catch (Exception e) {
				log.error("error while trying to send the saml auth request:"
						+ e);
				e.printStackTrace();
			}
		}

		return user;
	}

	private Response getSamlResponse(String certificate,
									 String responseEncrypted,
									 String relayState) throws Exception {
		AccountSettings accountSettings = new AccountSettings();
		accountSettings.setCertificate(certificate);

		Response samlResponse = new Response(accountSettings,
											 responseEncrypted,
											 relayState);
		log.debug("samlResponse" + samlResponse.toString());
		return samlResponse;
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

	@Override
	protected Principal getUser(String username) {
		return ComponentAccessor.getUserManager().getUserByName(username);
	}

	@Override
	protected boolean authenticate(Principal prncpl, String string)
			throws AuthenticatorException {
		String username = prncpl.getName();
  		log.debug(String.format("Checking whether %s is whitelisted.", username));
		if (isUserWhitelisted(username)) {
  			log.debug(String.format("User %s is whitelisted.", username));
  			return super.authenticate(prncpl, string);
  		}
		
  		return false;
	}

  	// Checks whether user is a member of the whitelisted JIRA group
	private boolean isUserWhitelisted(String username) {
		if (username == null || username.isEmpty()) {
			return false;
		}

		GroupManager groupManager = ComponentAccessor.getGroupManager();
		Collection<String> userGroups = groupManager.getGroupNamesForUser(username);
		log.debug(String.format("User: %s is a member of: %s ", username, userGroups.toString()));

		boolean isAllowed = false;
		if (userGroups.contains(WHITELISTED_GROUP)) {
			log.debug(String.format("User is a memeber of whitelisted group: %s.", WHITELISTED_GROUP));
			isAllowed = true;
		}
		return isAllowed;
	}
}
