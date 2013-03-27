package com.atlassian.jira.security.login;

/*import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.exception.AccountNotFoundException;
import com.atlassian.crowd.exception.FailedAuthenticationException;
import com.atlassian.crowd.exception.runtime.CommunicationException;
import com.atlassian.crowd.exception.runtime.OperationFailedException;
//import com.atlassian.jira.ComponentManager;
//import com.atlassian.jira.user.util.OSUserConverter; */
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.jira.user.UserUtils;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import java.security.Principal;

// Referenced classes of package com.atlassian.jira.security.login:
//            PrincipalInSessionPlacer

public class JiraSeraphAuthenticator extends DefaultAuthenticator
{

	@Override
	protected boolean authenticate(Principal arg0, String arg1)
			throws AuthenticatorException {
		int x =1;
                x++;
		return false;
	}

	@Override
	protected Principal getUser(String username) {
        // TODO Auto-generated method stub
        //return null;
        int x =1;
        x++;    
        User user = UserUtils.getUser(username);
        return user;
	}

        
/*	
    private static final Logger log = Logger.getLogger(JiraSeraphAuthenticator.class);
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

    @Override
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
