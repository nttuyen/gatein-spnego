/*
 * Copyright (C) 2012 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.gatein.security.sso.spnego;

import java.lang.reflect.Method;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.services.security.jaas.AbstractLoginModule;
import org.exoplatform.web.security.AuthenticationRegistry;

public class SPNEGOLoginModule extends AbstractLoginModule {
    private static final Log log = ExoLogger.getLogger(SPNEGOLoginModule.class);

   /* *//** JACC get context method. *//*
    private static Method getContextMethod;

    static {
        try {
            Class<?> policyContextClass = Thread.currentThread().getContextClassLoader().loadClass("javax.security.jacc.PolicyContext");
            getContextMethod = policyContextClass.getDeclaredMethod("getContext", String.class);
        } catch (ClassNotFoundException ignore) {
            log.debug("JACC not found ignoring it", ignore);
        } catch (Exception e) {
            log.error("Could not obtain JACC get context method", e);
        }
    }*/

    @Override
    protected Log getLogger() {
        return log;
    }

    @Override
    public boolean login() throws LoginException {
        try {
            ExoContainer container = getContainer();

            HttpServletRequest servletRequest = getCurrentHttpServletRequest();
            if (servletRequest == null) {
                log.debug("HttpServletRequest is null. SPNEGOLoginModule will be ignored.");
                return false;
            }

            //AuthenticationRegistry registry = container.getComponentInstanceOfType(AuthenticationRegistry.class);
            //String username = (String)registry.getAttributeOfClient(servletRequest, "SPNEGO_PRINCIPAL");
            HttpSession session = servletRequest.getSession();
            String username = (String)session.getAttribute("SPNEGO_PRINCIPAL");
            if(username != null) {
                establishSecurityContext(container, username);
                if (log.isTraceEnabled()) {
                    log.trace("Successfully established security context for user " + username);
                }
                return true;
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }

    protected void establishSecurityContext(ExoContainer container, String username) throws Exception {
        Authenticator authenticator = container.getComponentInstanceOfType(Authenticator.class);

        if (authenticator == null) {
            throw new LoginException("No Authenticator component found, check your configuration");
        }

        Identity identity = authenticator.createIdentity(username);

        sharedState.put("exo.security.identity", identity);
        sharedState.put("javax.security.auth.login.name", username);
        subject.getPublicCredentials().add(new UsernameCredential(username));
    }


    // Forked from SSOLoginModule
    protected HttpServletRequest getCurrentHttpServletRequest() {
        HttpServletRequest request = null;

//        // JBoss way
//        if (getContextMethod != null) {
//            try {
//                request = (HttpServletRequest)getContextMethod.invoke(null, "javax.servlet.http.HttpServletRequest");
//            } catch(Throwable e) {
//                log.error("LoginModule error. Turn off session credentials checking with proper configuration option of " +
//                        "LoginModule set to false");
//                log.error(this, e);
//            }
//        } else {
            // Tomcat way (Assumed that ServletAccessValve has been configured in context.xml)
            try {
                // TODO: improve this
                Class<?> clazz = Thread.currentThread().getContextClassLoader().loadClass("org.gatein.sso.agent.tomcat.ServletAccess");
                Method getRequestMethod = clazz.getDeclaredMethod("getRequest");
                request = (HttpServletRequest)getRequestMethod.invoke(null);
            } catch (Exception e) {
                log.error("Unexpected exception when trying to obtain HttpServletRequest from ServletAccess thread-local", e);
            }
//        }

        if (log.isTraceEnabled()) {
            log.trace("Returning HttpServletRequest " + request);
        }

        return request;
    }
}
