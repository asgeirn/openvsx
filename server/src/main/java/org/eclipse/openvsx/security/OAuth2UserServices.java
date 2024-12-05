/********************************************************************************
 * Copyright (c) 2020 TypeFox and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx.security;

import jakarta.persistence.EntityManager;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.openvsx.UserService;
import org.eclipse.openvsx.eclipse.EclipseService;
import org.eclipse.openvsx.entities.UserData;
import org.eclipse.openvsx.repositories.RepositoryService;
import org.eclipse.openvsx.util.ErrorResultException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;

import static org.eclipse.openvsx.security.CodedAuthException.*;

@Service
public class OAuth2UserServices {

    private static final Logger log = LoggerFactory.getLogger(OAuth2UserServices.class);
    private final UserService users;
    private final TokenService tokens;
    private final RepositoryService repositories;
    private final EntityManager entityManager;
    private final EclipseService eclipse;
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2;
    private final OAuth2UserService<OidcUserRequest, OidcUser> oidc;

    public OAuth2UserServices(
            UserService users,
            TokenService tokens,
            RepositoryService repositories,
            EntityManager entityManager,
            EclipseService eclipse
    ) {
        this.users = users;
        this.tokens = tokens;
        this.repositories = repositories;
        this.entityManager = entityManager;
        this.eclipse = eclipse;
        this.oauth2 = new OAuth2UserService<OAuth2UserRequest, OAuth2User>() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
                return OAuth2UserServices.this.loadUser(userRequest);
            }
        };
        this.oidc = new OAuth2UserService<OidcUserRequest, OidcUser>() {
            @Override
            public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
                return OAuth2UserServices.this.loadUser(userRequest);
            }
        };
    }

    public OAuth2UserService<OAuth2UserRequest, OAuth2User> getOauth2() {
        return oauth2;
    }

    public OAuth2UserService<OidcUserRequest, OidcUser> getOidc() {
        return oidc;
    }

    @EventListener
    public void authenticationSucceeded(AuthenticationSuccessEvent event) {
        // We can assume that `UserData` already exists, because this event is fired after
        // `ExtendedOAuth2UserServices.loadUser` was processed.
        if (event.getSource() instanceof OAuth2LoginAuthenticationToken) {
            var auth = (OAuth2LoginAuthenticationToken) event.getSource();
            var idPrincipal = (IdPrincipal) auth.getPrincipal();
            var accessToken = auth.getAccessToken();
            var refreshToken = auth.getRefreshToken();
            var registrationId = auth.getClientRegistration().getRegistrationId();

            tokens.updateTokens(idPrincipal.getId(), registrationId, accessToken, refreshToken);
        }
    }

    public IdPrincipal loadUser(OAuth2UserRequest userRequest) {
        var registrationId = userRequest.getClientRegistration().getRegistrationId();
        switch (registrationId) {
            case "github":
                return loadGitHubUser(userRequest);
            case "eclipse":
                return loadEclipseUser(userRequest);
            default:
                //throw new CodedAuthException("Unsupported registration: " + registrationId, UNSUPPORTED_REGISTRATION);
                return loadGenericUser(registrationId, userRequest);
        }
    }

    private IdPrincipal loadGenericUser(String registrationId, OAuth2UserRequest userRequest) {
        log.debug("Authorization for registration {}", registrationId);
        OAuth2AccessToken accessToken = userRequest.getAccessToken();
        log.debug("Access token {}, scopes = {}", accessToken.getTokenType().getValue(), accessToken.getScopes());
        var authUser = delegate.loadUser(userRequest);
        log.debug("User name: {}", authUser.getName());
        authUser.getAttributes().forEach((k, v) -> log.debug("User: {} = {}", k, v));
        authUser.getAuthorities().forEach(k -> log.debug("Authority: {}", k));
        var userData = repositories.findUserByLoginName(registrationId, authUser.getName());
        if (userData == null) {
            log.debug("User not found, creating ...");
            userData = users.registerNewUser(registrationId, authUser);
        } else {
            log.debug("Updating existing user...");
            userData = users.updateExistingUser(userData, authUser);
        }
        log.debug("User: {}", userData);
        return new IdPrincipal(userData.getId(), authUser.getName(), getAuthorities(userData));
    }

    private IdPrincipal loadGitHubUser(OAuth2UserRequest userRequest) {
        var authUser = delegate.loadUser(userRequest);
        String loginName = authUser.getAttribute("login");
        if (StringUtils.isEmpty(loginName))
            throw new CodedAuthException("Invalid login: missing 'login' field.", INVALID_GITHUB_USER);
        var userData = repositories.findUserByLoginName("github", loginName);
        if (userData == null)
            userData = users.registerNewUser(authUser);
        else
            users.updateExistingUser(userData, authUser);
        return new IdPrincipal(userData.getId(), authUser.getName(), getAuthorities(userData));
    }

    private IdPrincipal loadEclipseUser(OAuth2UserRequest userRequest) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null)
            throw new CodedAuthException("Please log in with GitHub before connecting your Eclipse account.",
                    NEED_MAIN_LOGIN);
        if (!(authentication.getPrincipal() instanceof IdPrincipal))
            throw new CodedAuthException("The current authentication is invalid.", NEED_MAIN_LOGIN);
        var principal = (IdPrincipal) authentication.getPrincipal();
        var userData = entityManager.find(UserData.class, principal.getId());
        if (userData == null)
            throw new CodedAuthException("The current authentication has no backing data.", NEED_MAIN_LOGIN);
        try {
            var accessToken = userRequest.getAccessToken().getTokenValue();
            var profile = eclipse.getUserProfile(accessToken);
            if (StringUtils.isEmpty(profile.getGithubHandle()))
                throw new CodedAuthException("Your Eclipse profile is missing a GitHub username.",
                        ECLIPSE_MISSING_GITHUB_ID);
            if (!profile.getGithubHandle().equalsIgnoreCase(userData.getLoginName()))
                throw new CodedAuthException("The GitHub username setting in your Eclipse profile ("
                        + profile.getGithubHandle()
                        + ") does not match your GitHub authentication ("
                        + userData.getLoginName() + ").",
                        ECLIPSE_MISMATCH_GITHUB_ID);

            eclipse.updateUserData(userData, profile);
            return principal;
        } catch (ErrorResultException exc) {
            throw new AuthenticationServiceException(exc.getMessage(), exc);
        }
    }

    private Collection<GrantedAuthority> getAuthorities(UserData userData) {
        var role = userData.getRole();
        switch (role != null ? role : "") {
            case UserData.ROLE_ADMIN:
                return AuthorityUtils.createAuthorityList("ROLE_ADMIN");
            case UserData.ROLE_PRIVILEGED:
                return AuthorityUtils.createAuthorityList("ROLE_PRIVILEGED");
            default:
                return Collections.emptyList();
        }
    }

}