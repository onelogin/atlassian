package com.onelogin.confluence.saml;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.log4j.Logger;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.interceptor.DefaultTransactionAttribute;
import org.springframework.transaction.interceptor.TransactionAttribute;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;
import org.xml.sax.SAXException;

import com.atlassian.confluence.event.events.security.LoginEvent;
import com.atlassian.confluence.event.events.security.LoginFailedEvent;
import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.crowd.EmbeddedCrowdBootstrap;
import com.atlassian.crowd.dao.application.ApplicationDAO;
import com.atlassian.crowd.directory.DelegatedAuthenticationDirectory;
import com.atlassian.crowd.directory.RemoteDirectory;
import com.atlassian.crowd.directory.loader.DirectoryInstanceLoader;
import com.atlassian.crowd.embedded.api.Directory;
import com.atlassian.crowd.embedded.api.DirectoryType;
import com.atlassian.crowd.embedded.atlassianuser.EmbeddedCrowdUser;
import com.atlassian.crowd.event.user.UserAuthenticatedEvent;
import com.atlassian.crowd.exception.ApplicationNotFoundException;
import com.atlassian.crowd.exception.DirectoryInstantiationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.manager.application.ApplicationService;
import com.atlassian.crowd.model.application.Application;
import com.atlassian.crowd.model.application.DirectoryMapping;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.auth.LoginReason;
import com.atlassian.spring.container.ContainerManager;
import com.atlassian.user.User;
import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

public class SSOAuthenticator extends ConfluenceAuthenticator {

    private static final Logger log = Logger.getLogger(SSOAuthenticator.class);
    public String reqString = "";

    public SSOAuthenticator() {
    }

    
    
    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        
        log.debug(" getUser ");
        //System.out.println(" getUser ");
        Principal user = null;
        HashMap<String, String> configValues = getConfigurationValues("conf_onelogin.xml");
        String sSAMLResponse = request.getParameter("SAMLResponse");
		String os_destination = request.getParameter("os_destination");

		boolean samlResponseValidated = false;
		if (os_destination != null){
			request.getSession().setAttribute("os_destination", os_destination);
			log.warn(" os_destination: " + os_destination);
			//System.out.println(" os_destination: " + os_destination);
		}
        try {

            if (sSAMLResponse != null) {
            	
            	//System.out.println("SAML Response not null");

               request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY,  null);
               request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
                
                final String remoteIP = request.getRemoteAddr();
                final String remoteHost = request.getRemoteHost();


                   Response samlResponse = getSamlResponse(configValues.get("certificate"),request.getParameter("SAMLResponse"));

                if (samlResponse.isValid()) {
                    // The signature of the SAML Response is valid. The source is trusted
                    String sNameId = samlResponse.getNameId();
                    log.info(String.format("Checking internal DB for user %s", sNameId));
                    //System.out.println(String.format("Checking internal DB for user %s", sNameId));
                    user = getUser(sNameId);
                    
                    if (user == null){
                      log.info(String.format("User %s not found within local DB, searching directories...", sNameId));
                      //System.out.println(String.format("User %s not found within local DB, searching directories...", sNameId));
                      user = validateLdapUser(sNameId);
                    }
                    
                    if(user!=null){
                        log.info("login from user: "+sNameId );
                        //System.out.println("login from user: "+sNameId );
                        putPrincipalInSessionContext(request, user);
                        getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, sNameId);
                        LoginReason.OK.stampRequestResponse(request, response);
                        // Firing this event is necessary to ensure the user's personal information is initialized correctly.
                        getEventPublisher().publish(new LoginEvent(this, sNameId, request.getSession().getId(), remoteHost, remoteIP, LoginEvent.UNKNOWN));
                        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
                        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
						log.warn("User sucessfully logged in " + sNameId);
						String relayState = request.getSession().getAttribute("RelayState").toString();
						if(relayState != null && !relayState.isEmpty() && relayState.contains(request.getServerName())){
							request.getSession().setAttribute("redirect", true);
						}else{
							request.getSession().setAttribute("redirect", false);
						}
						
                    }else{
                        log.error("user: "+sNameId+" could not be found");
                        //System.out.println("user: "+sNameId+" could not be found");
                        getElevatedSecurityGuard().onFailedLoginAttempt(request, sNameId);
                        getEventPublisher().publish(new LoginFailedEvent(this, sNameId, request.getSession().getId(), remoteHost, remoteIP));
                        request.setAttribute("samlInvalid", "true");
                        return null;
                    }
                    
                } else {
					request.setAttribute("samlInvalid", "true");
					log.error("SAML Response is not valid");
					log.warn(sSAMLResponse);
					//System.out.println(sSAMLResponse);
                }
				samlResponseValidated = true;
            } else if (request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null) {
                log.info("Session found; user already logged in");
                //System.out.println("Session found; user already logged in");
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
                String relayState = null;
                if(os_destination != null){
                	relayState = request.getRequestURL().toString().replace(request.getRequestURI(), os_destination);
                	request.getSession().setAttribute("RelayState", relayState);
                 }
                reqString = authReq.getSSOurl(accSettings.getIdp_sso_target_url(), relayState);   			
                log.debug("reqString : " +reqString );
                //System.out.println("reqString : " +reqString );
                request.getSession().setAttribute("reqString", reqString); 
            }

        } catch (Exception e) {
            log.error("error while trying to send the saml auth request:" , e);
            //System.out.println("error while trying to send the saml auth request:"  + e.getMessage());
            e.printStackTrace();
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

    private Response getSamlResponse(String certificate,String responseEncrypted) throws CertificateException, ParserConfigurationException, SAXException, IOException, XPathExpressionException {
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
    
    
    /**
     * If the Confluence system is configured with one or more LDAP-based user directories, there is some
     * plumbing code we must churn out in order to ensure that all the advanced features of Confluence's LDAP
     * integration will work successfully.
     * 
     * In particular, these features will not work in an SSO environment without this code:
     * 
     * Default Group Memberships (any LDAP-enabled directory)
     * Copy User On First Login (only for internal directories with delegated LDAP authentication)
     * Synchronise Group Memberships (only for internal directories with delegated LDAP authentication)
     * 
     * These features are implemented in such a way that they require an "authentication" process to take place
     * against the LDAP directory. Because, in an SSO environment, we don't do any actual authentication, this
     * 'post-login' processing never executes unless we trigger it manually.
     *
     * @param username The username to be set as the authenticated user for this session.
     * @return A valid User object for the specified user, if the user was found in any of the LDAP-based
     *         directories configured in Confluence that are not disabled. If the user is not found, null is returned
     *         (the user may still be a valid user in another directory, such as the Confluence internal directory, or the
     *         communication with the correct LDAP directory may have failed).
     */
    protected User validateLdapUser(final String username)
    {
        // If we do find the user in an LDAP directory, write operations on the Confluence database may be caused in order
        // to copy the new user into an internal directory (for delegated auth directories) and synchronise group memberships.
        // We need to wrap this code in a new read/write transaction in order for this to work
        TransactionDefinition transactionDefinition = new DefaultTransactionAttribute(TransactionAttribute.PROPAGATION_REQUIRED);
        final EmbeddedCrowdUser user = (EmbeddedCrowdUser) new TransactionTemplate(getTransactionManager(), transactionDefinition).execute(new TransactionCallback()
        {
            public Object doInTransaction(TransactionStatus transactionStatus)
            {
                final Application application;
                try
                {
                    application = getApplicationDao().findByName(EmbeddedCrowdBootstrap.APPLICATION_NAME);
                }
                catch (ApplicationNotFoundException e)
                {
                    // Unable to load the Application singleton from Embedded Crowd; something is seriously wrong.
                    log.error(String.format("Unable to load Application singleton %s: %s", e.getMessage(), e.toString()));
                    return null;
                }

                // Iterate through the application's configured directories and search any LDAP-based directory for the desired user
                Iterable<Directory> activeDirectories = getActiveLdapDirectories(application);
                for (Directory dir : activeDirectories)
                {
                    try
                    {
                        log.info(String.format("Enumerating directory %s (%s): %s", String.valueOf(dir.getId()), dir.getName(), dir.getDescription()));
                        log.info(String.format("The directory is of type %s", dir.getType().toString()));

                        // Retrieve the corresponding remote directory object.
                        RemoteDirectory remoteDir;
                        remoteDir = getDirectoryLoader().getDirectory(dir);

                        // If the directory is configured for Delegated LDAP Authentication, we may need to handle the situation
                        // where this is the first time the user has logged in and the directory is configured to "Copy User On Login".
                        // We need to tell the directory to copy the user into the internal directory.
                        com.atlassian.crowd.model.user.User crowdUser;
                        if (remoteDir instanceof DelegatedAuthenticationDirectory)
                        {
                            log.info("Forcing optional 'Copy User on Login' and 'Group Import' processing.");
                            // This call may cause write operations on the Confluence database in order to copy the new user and
                            // sync group memberships.
                            crowdUser = ((DelegatedAuthenticationDirectory) remoteDir).addOrUpdateLdapUser(username);
                        }
                        else
                        {
                            log.debug("Locating user in directory");
                            crowdUser = remoteDir.findUserByName(username);
                        }

                        // If the user is found, trigger the 'Default Group Memberships' behaviour that may be configured on the directory.
                        triggerUserAuthenticatedEvent(application, dir, crowdUser);
                        return new EmbeddedCrowdUser(crowdUser); // Wrap up the crowd user object in a principal that can be injected into the Session.
                    }
                    catch (DirectoryInstantiationException e)
                    {
                        log.error(String.format("Unable to instantiate the desired RemoteDirectory; skipping (%s: %s)", e.getMessage(), e.toString()));
                    }
                    catch (UserNotFoundException e)
                    {
                        log.debug("User not found in this directory; skipping.");
                    }
                    catch (OperationFailedException e)
                    {
                        log.error(String.format("Failed to check directory for user; skipping (%s: %s)", e.getMessage(), e.toString()));
                    }
                }

                log.info("The requested username does not appear to be a valid user in any configured LDAP directory.");
                return null;
            }
        });
        return user;
    }
   
    
     private void triggerUserAuthenticatedEvent(Application application, Directory directory, com.atlassian.crowd.model.user.User user)
    {
        log.debug(String.format("Firing UserAuthenticatedEvent for User %s in Directory %s", user.getName(), directory.getName()));

        // Fire the event.
        getEventPublisher().publish(new UserAuthenticatedEvent(getApplicationService(), directory, application, user));
    }

    /**
     * Returns all configured LDAP Directories and Delegated LDAP Auth Directories that are not currently disabled. The
     * set of directories are theoretically returned in the correct priority order.
     *
     * @param application The Embedded Crowd {@link Application} singleton.
     * @return A set of {@link Directory} objects that match the desired criteria.
     */
    private Iterable<Directory> getActiveLdapDirectories(final Application application)
    {
        return Iterables.filter(Iterables.transform(application.getDirectoryMappings(), new Function<DirectoryMapping, Directory>()
        {
            public Directory apply(final DirectoryMapping from)
            {
                return from.getDirectory();
            }
        }), new Predicate<Directory>()
        {
            public boolean apply(final Directory from)
            {
                return (from.isActive() && (from.getType().equals(DirectoryType.DELEGATING) || from.getType().equals(DirectoryType.CONNECTOR)));
            }
        });
    }

    private PlatformTransactionManager transactionManager;

    private PlatformTransactionManager getTransactionManager()
    {
        if (transactionManager == null)
            transactionManager = (PlatformTransactionManager) ContainerManager.getComponent("transactionManager");

        return transactionManager;
    }

    private ApplicationService applicationService;

    private ApplicationService getApplicationService()
    {
        if (applicationService == null)
            applicationService = (ApplicationService) ContainerManager.getComponent("crowdApplicationService");

        return applicationService;
    }

    private ApplicationDAO applicationDao;

    private ApplicationDAO getApplicationDao()
    {
        if (applicationDao == null)
            applicationDao = (ApplicationDAO) ContainerManager.getComponent("embeddedCrowdApplicationDao");

        return applicationDao;
    }

    private DirectoryInstanceLoader directoryLoader;

    private DirectoryInstanceLoader getDirectoryLoader()
    {
        if (directoryLoader == null)
            directoryLoader = (DirectoryInstanceLoader) ContainerManager.getComponent("directoryInstanceLoader");

        return directoryLoader;
    }
}