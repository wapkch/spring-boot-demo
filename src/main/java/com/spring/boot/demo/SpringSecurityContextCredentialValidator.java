/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.spring.boot.demo;

import com.google.common.collect.Lists;

import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;

import org.apache.velocity.VelocityContext;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.ldaptive.Credential;
import org.ldaptive.LdapException;
import org.ldaptive.ResultCode;
import org.ldaptive.auth.AccountState;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.AuthenticationResultCode;
import org.ldaptive.auth.Authenticator;
import org.ldaptive.auth.User;
import org.ldaptive.jaas.LdapPrincipal;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.AbstractCredentialValidator;
import net.shibboleth.idp.authn.AbstractUsernamePasswordCredentialValidator;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.CredentialValidator;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.LDAPResponseContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * A password validator that authenticates against LDAP natively.
 * 
 * @since 4.0.0
 */
@ThreadSafeAfterInit
public class SpringSecurityContextCredentialValidator implements CredentialValidator {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(SpringSecurityContextCredentialValidator.class);

    @Nullable
    @Override
    public Subject validate(@NotNull ProfileRequestContext profileRequestContext, @NotNull AuthenticationContext authenticationContext, @Nullable CredentialValidator.WarningHandler warningHandler, @Nullable CredentialValidator.ErrorHandler errorHandler) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        final Subject subject = new Subject();
        subject.getPrincipals().add(new UsernamePrincipal("system@gaia.com"));

        IdPAttribute mail = new IdPAttribute("mail");
        mail.setValues(Lists.newArrayList(new StringAttributeValue("chao.wang@zatech.com")));
        subject.getPrincipals().add(new IdPAttributePrincipal(mail));

        return subject;
    }

    private String id;

    @Override
    public void setId(@NotNull String componentId) {
        this.id = componentId;
    }

    @Nullable
    @Override
    public String getId() {
        return id;
    }

}