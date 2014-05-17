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

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.UUID;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.web.filter.Filter;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class SPNEGOFilter implements Filter {
    private static final Log log = ExoLogger.getLogger(SPNEGOLoginModule.class);
    private static final GSSManager MANAGER = GSSManager.getInstance();
    private static final BASE64Encoder base64Encoder = new BASE64Encoder();
    private static final BASE64Decoder base64Decoder = new BASE64Decoder();

    private LoginContext loginContext;

    public SPNEGOFilter() {
        try {
            this.loginContext = new LoginContext("spnego-server");
            loginContext.login();
        } catch (Exception ex) {
            log.warn("Exception when init LoginContext, so SPNEGO SSO login will not work", ex);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest)request;
        final HttpServletResponse resp = (HttpServletResponse)response;
        final String contextPath = req.getContextPath();
        final String loginURL = contextPath + "/login";
        SPNEGOContext.setCurrentRequest(req);

        String requestURL = req.getRequestURI();
        String username = req.getParameter("username");
        String remoteUser = req.getRemoteUser();
        if(username != null || remoteUser != null) {
            chain.doFilter(req, resp);
            return;
        }

        String principal = null;
        String auth = req.getHeader("Authorization");
        if(auth != null) {
            try {
                principal = this.login(req, resp, auth);
            } catch (Exception ex) {
                log.error("Exception occur when trying to login with SPNEGO", ex);
            }
        }

        if(principal != null && !principal.isEmpty()) {
            username = principal.substring(0, principal.indexOf('@'));
            // We don't need user password when he login using SSO (SPNEGO)
            // But LoginServlet require password is not empty to call login action instead of display input form
            // So, we need to generate a random password
            String password = UUID.randomUUID().toString();

            HttpSession session = req.getSession();
            session.setAttribute("SPNEGO_PRINCIPAL", username);

            StringBuilder login = new StringBuilder(loginURL)
                    .append("?username=")
                    .append(username)
                    .append("&password=")
                    .append(password);
            String initURL = req.getParameter("initialURI");
            if(initURL != null) {
                login.append("&initialURI=").append(initURL);
            }

            resp.sendRedirect(login.toString());
        } else {
            if(!loginURL.equalsIgnoreCase(requestURL)) {
                RequestDispatcher dispatcher = req.getRequestDispatcher("/login");
                dispatcher.include(req, resp);
            } else {
                chain.doFilter(req, resp);
            }
            resp.setHeader("WWW-Authenticate", "Negotiate");
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private String login(HttpServletRequest req, HttpServletResponse resp, String auth) throws Exception {
        if(this.loginContext == null) {
            return null;
        }

        final String principal;
        final String tok = auth.substring("Negotiate".length() + 1);
        final byte[] gss = base64Decoder.decodeBuffer(tok);


        GSSContext context = null;
        byte[] token = null;
        context = MANAGER.createContext(getServerCredential(loginContext.getSubject()));
        token = context.acceptSecContext(gss, 0, gss.length);

        if (null == token) {
            return null;
        }

        resp.setHeader("WWW-Authenticate", "Negotiate" + ' ' + base64Encoder.encode(token));

        if (!context.isEstablished()) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        }

        principal = context.getSrcName().toString();
        context.dispose();

        return principal;
    }


    /**
     * Returns the {@link org.ietf.jgss.GSSCredential} the server uses for pre-authentication.
     *
     * @param subject account server uses for pre-authentication
     * @return credential that allows server to authenticate clients
     * @throws java.security.PrivilegedActionException
     */
    static GSSCredential getServerCredential(final Subject subject)
            throws PrivilegedActionException {

        final PrivilegedExceptionAction<GSSCredential> action =
                new PrivilegedExceptionAction<GSSCredential>() {
                    public GSSCredential run() throws GSSException {
                        return MANAGER.createCredential(
                                null
                                , GSSCredential.INDEFINITE_LIFETIME
                                , getOid()
                                , GSSCredential.ACCEPT_ONLY);
                    }
                };
        return Subject.doAs(subject, action);
    }

    /**
     * Returns the Universal Object Identifier representation of
     * the SPNEGO mechanism.
     *
     * @return Object Identifier of the GSS-API mechanism
     */
    private static Oid getOid() {
        Oid oid = null;
        try {
            oid = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException gsse) {
            gsse.printStackTrace();
        }
        return oid;
    }
}
