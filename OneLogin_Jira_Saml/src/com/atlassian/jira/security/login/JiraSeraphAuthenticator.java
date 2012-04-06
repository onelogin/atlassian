package com.atlassian.jira.security.login;

import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.exception.AccountNotFoundException;
import com.atlassian.crowd.exception.FailedAuthenticationException;
import com.atlassian.crowd.exception.runtime.CommunicationException;
import com.atlassian.crowd.exception.runtime.OperationFailedException;
// import com.atlassian.jira.ComponentManager;
// import com.atlassian.jira.user.util.OSUserConverter;
import com.atlassian.seraph.auth.*;
import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

// Referenced classes of package com.atlassian.jira.security.login:
//            PrincipalInSessionPlacer

public class JiraSeraphAuthenticator extends DefaultAuthenticator
{

	@Override
	protected boolean authenticate(Principal arg0, String arg1)
			throws AuthenticatorException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	protected Principal getUser(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}
	
	/*
	private static final Logger log = Logger.getLogger(com/atlassian/jira/security/login/JiraSeraphAuthenticator);
    private final PrincipalInSessionPlacer principalInSession = new PrincipalInSessionPlacer();

    public JiraSeraphAuthenticator()
    {
    }

    protected Principal getUser(String username)
    {
        return OSUserConverter.convertToOSUser(getCrowdService().getUser(username));
    }

    protected boolean authenticate(Principal user, String password)
        throws AuthenticatorException
    {
        crowdServiceAuthenticate(user, password);
        return true;
        AccountNotFoundException e;
        e;
        log.debug((new StringBuilder()).append("authenticate : '").append(user.getName()).append("' does not exist and cannot be authenticated.").toString());
        return false;
        e;
        return false;
        CommunicationException ex;
        ex;
        throw new AuthenticatorException(AuthenticationErrorType.CommunicationError);
        ex;
        log.error((new StringBuilder()).append("Error occurred while trying to authenticate user '").append(user.getName()).append("'.").toString(), ex);
        throw new AuthenticatorException(AuthenticationErrorType.UnknownError);
    }

    private void crowdServiceAuthenticate(Principal user, String password)
        throws FailedAuthenticationException
    {
        Thread currentThread;
        ClassLoader origCCL;
        currentThread = Thread.currentThread();
        origCCL = currentThread.getContextClassLoader();
        currentThread.setContextClassLoader(getClass().getClassLoader());
        getCrowdService().authenticate(user.getName(), password);
        currentThread.setContextClassLoader(origCCL);
        break MISSING_BLOCK_LABEL_58;
        Exception exception;
        exception;
        currentThread.setContextClassLoader(origCCL);
        throw exception;
    }

    protected void putPrincipalInSessionContext(HttpServletRequest httpServletRequest, Principal principal)
    {
        principalInSession.putPrincipalInSessionContext(httpServletRequest, principal);
    }

    private CrowdService getCrowdService()
    {
        return (CrowdService)ComponentManager.getComponent(com/atlassian/crowd/embedded/api/CrowdService);
    }
	*/
}
