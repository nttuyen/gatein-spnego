SPNEGO SSO implement for gatein tomcat packaging

###Build and configure

1. Configure SPNEGO Server
  You configure SPNEGO server follow the guideline at gatein document: https://docs.jboss.org/author/display/GTNPORTAL37/SPNEGO

2. Build and deploy gatein-spnego
  - Use maven to build gatein-spnego project
  - Copy gatein-spnego-${VERSION}.jar to $GATEIN_TOMCAT/lib folder

3. Configure gatein
  - Append this login module configuration into $GATEIN_HOME/conf/jaas.conf
```
spnego-server {
	com.sun.security.auth.module.Krb5LoginModule required
	storeKey=true
	doNotPrompt=true
	useKeyTab=true
	keyTab="/etc/krb5.keytab"
	principal="HTTP/server.local.network@LOCAL.NETWORK"
	useFirstPass=true
	debug=true
	isInitiator=false;
};
```

  - Change SSO section in the file $GATEIN_HOME/gatein/conf/configuration.properties to be like this:
```
gatein.sso.enabled=true
gatein.sso.callback.enabled=false
gatein.sso.skip.jsp.redirection=false
gatein.sso.login.module.enabled=true
gatein.sso.login.module.class=org.gatein.security.sso.spnego.SPNEGOLoginModule
gatein.sso.filter.login.sso.url=/@@portal.container.name@@/spnegosso
gatein.sso.filter.initiatelogin.enabled=false
gatein.sso.valve.enabled=false
gatein.sso.filter.logout.enabled=false
```

