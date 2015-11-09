# Atlassian Plugins
## OneLogin Authenticators for Confluence and Jira

Overview
-----
The included projects are for the purpose of autheticating with Atlassian's Jira and Confluence. 
Documentation for setting up a particular project for a particular purposes is included in each project. 
That is to say documentation for setting up and configuring Confluence is in the confluence directory. 
Documentation for Jira is in the Jira directories.


Builds
-----
These projects are written in Java and the builds are based on Maven. Requirements for building include:

1. A current version of Java
2. A current version of Maven. (For details on Maven see https://maven.apache.org/.)

Builds have been tested with Java version 1.8.0_60 and Maven 3.3.3. The version of Java you choose to build with will be dependent on the requirements of your use case.

To build one of the Atlassian projects:

1. Sync to the latest of onlogin/atlassian
2. cd to the project you would like to build. For example confluence/version4
3. run 'mvn clean install'

The build for confluence version4 may require you to add the customauth-conf jar file to your local maven repo. To do so run the following command from the version4 directory 'mvn install:install-file -Dfile=customauth-conf-0.4.jar -DgroupId=com.onelogin -DartifactId=customauth-conf -Dversion=0.4 -Dpackaging=jar'

The build for Jira version4 may require that you add the customauth-jira jar file to your local maven repo. To do so run the following command from the jira/version4 directory 'mvn install:install-file -Dfile=customauth-jira-0.4.jar -DgroupId=com.onelogin -DartifactId=customauth-jira -Dversion=0.4 -Dpackaging=jar'

The build for Jira version6 has an additional dependency, the latest OneLogin java-saml jar (java-saml-1.1.2.jar), from the onelogin/java-saml project on GitHub. So for building Jira version6 the steps are: 

1. Sync onelogin/java-saml
2. Build onelogin/java-saml (it's also a Maven/Java project). 
3. Run 'mvn clean install' to place the java-saml-1.1.2.jar in your local Maven repository
4. Next pull the lastest from onelogin/atlassian and run 'mvn install' from version6 to bulid your Jira version6 artifacts as above.

