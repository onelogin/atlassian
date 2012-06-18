<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:useBean id="SSOAuthenticator" scope="session" class="com.onelogin.confluence.saml.SSOAuthenticator"></jsp:useBean>

<%
	if(request.getParameter("SAMLResponse") == null)
	{
		String redirectURL = request.getSession().getAttribute("reqString").toString();
		response.sendRedirect(redirectURL);
	}
%>
