package com.spring.boot.demo;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.profile.SAML2NameIDGenerator;

public class SpringSecuritySAML2NameIDGenerator implements SAML2NameIDGenerator {
    @Nullable
    @Override
    public NameID generate(@NotNull ProfileRequestContext profileRequestContext, @NotNull String format) throws SAMLException {
        return null;
    }
}
