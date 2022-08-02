package com.spring.boot.demo;

import com.google.common.net.HttpHeaders;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.time.Instant;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.annotation.Nonnull;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.binding.expression.Expression;
import org.springframework.binding.expression.ExpressionParser;
import org.springframework.binding.expression.support.FluentParserContext;
import org.springframework.binding.mapping.impl.DefaultMapper;
import org.springframework.binding.mapping.impl.DefaultMapping;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.definition.FlowDefinition;
import org.springframework.webflow.engine.EndState;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.springframework.webflow.executor.FlowExecutor;
import org.springframework.webflow.executor.FlowExecutorImpl;
import org.springframework.webflow.expression.spel.WebFlowSpringELExpressionParser;
import org.springframework.webflow.test.MockExternalContext;
import org.w3c.dom.Element;

import net.shibboleth.ext.spring.config.BooleanToPredicateConverter;
import net.shibboleth.ext.spring.config.FunctionToFunctionConverter;
import net.shibboleth.ext.spring.config.PredicateToPredicateConverter;
import net.shibboleth.ext.spring.config.StringBooleanToPredicateConverter;
import net.shibboleth.ext.spring.config.StringToDurationConverter;
import net.shibboleth.ext.spring.config.StringToIPRangeConverter;
import net.shibboleth.ext.spring.config.StringToResourceConverter;
import net.shibboleth.idp.spring.IdPPropertiesApplicationContextInitializer;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.EncodingException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import net.shibboleth.utilities.java.support.net.RequestResponseContextFilter;
import net.shibboleth.utilities.java.support.net.SimpleURLCanonicalizer;
import net.shibboleth.utilities.java.support.net.URLBuilder;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.impl.Type4UUIDIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

@ImportResource(locations = {
    "/system/conf/global-system.xml",
    "/system/conf/mvc-beans.xml",
    "/system/conf/webflow-config.xml",
    "test-beans.xml",
    "override-beans.xml"
})
@SpringBootApplication
public class App {

    public static void main(String[] args) {
        new SpringApplicationBuilder(App.class)
            .initializers(
                new TestEnvironmentApplicationContextInitializer(),
                new PreferFileSystemApplicationContextInitializer(),
                new IdPPropertiesApplicationContextInitializer())
            .run(args);
    }

    @Bean
    public FilterRegistrationBean<RequestResponseContextFilter> localeFilterRegistration() {
        FilterRegistrationBean<RequestResponseContextFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RequestResponseContextFilter());
        registration.addUrlPatterns("/SAML2/Redirect/SSO");
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 4);
        return registration;
    }

    @Autowired
    private FlowExecutor flowExecutor;

//    @Bean
//    public ApplicationRunner applicationRunner() throws Exception {
//        MockHttpServletRequest request = new MockHttpServletRequest();
//        // add basic auth header for jdoe:changeit, see test-ldap.ldif
////        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic Y2hhby53YW5nOmNoYW5nZWl0");
//        MockHttpServletResponse response = new MockHttpServletResponse();
//        MockExternalContext externalContext = new MockExternalContext();
//        externalContext.setNativeRequest(request);
//        externalContext.setNativeResponse(response);
//
//        request.setMethod("GET");
//        request.setRequestURI("/idp/profile/" + "SAML2/Redirect/SSO");
//
//        final AuthnRequest authnRequest = buildAuthnRequest(request);
//        authnRequest.setDestination(getDestinationRedirect(request));
//
//        final MessageContext messageContext =
//            buildOutboundMessageContext(authnRequest, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
//        final SAMLObject message = (SAMLObject) messageContext.getMessage();
//        final String encodedMessage = encodeMessage(message);
//        request.addParameter("SAMLRequest", encodedMessage);
//
//        HttpServletRequestResponseContext.loadCurrent(request, response);
//
//        directoryServer =
//            new InMemoryDirectory(new ClassPathResource(LDIF_FILE), 10389, new ClassPathResource(KEYSTORE_FILE));
//        directoryServer.start();
//
//        return new ApplicationRunner() {
//
//            @Override
//            public void run(ApplicationArguments args) throws Exception {
//                overrideEndStateOutput("SAML2/Redirect/SSO", "end");
//
//                FlowExecutionResult flowExecutionResult =
//                    flowExecutor.launchExecution("SAML2/Redirect/SSO", null, externalContext);
//
//                HttpServletRequestResponseContext.clearCurrent();
//
//                if (directoryServer != null) {
//                    directoryServer.stop();
//                }
//            }
//        };
//    }

    public void overrideEndStateOutput(@Nonnull final String flowID, @Nonnull final String endStateId) {
        final FlowDefinition flow = getFlow(flowID);

        final ExpressionParser parser = new WebFlowSpringELExpressionParser(new SpelExpressionParser());
        final Expression source =
            parser.parseExpression(END_STATE_OUTPUT_ATTR_EXPR,
                new FluentParserContext().evaluate(RequestContext.class));
        final Expression target =
            parser.parseExpression(END_STATE_OUTPUT_ATTR_NAME,
                new FluentParserContext().evaluate(MutableAttributeMap.class));
        final DefaultMapping defaultMapping = new DefaultMapping(source, target);
        final DefaultMapper defaultMapper = new DefaultMapper();
        defaultMapper.addMapping(defaultMapping);

        final EndState endState = (EndState) flow.getState(endStateId);
        endState.setOutputMapper(defaultMapper);
    }

    @Nonnull public final static String END_STATE_OUTPUT_ATTR_EXPR = "flowRequestContext.getConversationScope().get('"
        + ProfileRequestContext.BINDING_KEY + "')";

    /** The name of the end state flow output attribute containing the profile request context. */
    @Nonnull public final static String END_STATE_OUTPUT_ATTR_NAME = "ProfileRequestContext";

    public Flow getFlow(@Nonnull final String flowID) {
        Constraint.isNotNull(flowID, "Flow ID can not be null");

        Constraint.isTrue(flowExecutor instanceof FlowExecutorImpl, "The flow executor must be an instance of "
            + FlowExecutorImpl.class);

        final FlowDefinition flowDefinition =
            ((FlowExecutorImpl) flowExecutor).getDefinitionLocator().getFlowDefinition(flowID);

        Constraint.isTrue(flowDefinition instanceof Flow, "The flow definition must be an instance of " + Flow.class);

        return (Flow) flowDefinition;
    }

    protected InMemoryDirectory directoryServer;

    @Nonnull public final static String LDIF_FILE = "/test/test-ldap.ldif";

    /** Path to keystore file to be used by the directory server. */
    @Nonnull public final static String KEYSTORE_FILE = "/test/test-ldap.keystore";

    @Nonnull
    public String encodeMessage(@Nonnull final SAMLObject message) throws MarshallingException, IOException, EncodingException {
        final Element domMessage = XMLObjectSupport.marshall(message);
        final String messageXML = SerializeSupport.nodeToString(domMessage);

        final ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        final Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        final DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
        deflaterStream.write(messageXML.getBytes("UTF-8"));
        deflaterStream.finish();

        return Base64Support.encode(bytesOut.toByteArray(), Base64Support.UNCHUNKED);
    }

    public String getDestinationRedirect(HttpServletRequest servletRequest) {
        // TODO servlet context
        String destinationPath = "/idp/profile/SAML2/Redirect/SSO";
        try {
            String baseUrl = SimpleURLCanonicalizer.canonicalize(getBaseUrl(servletRequest));
            URLBuilder urlBuilder = new URLBuilder(baseUrl);
            urlBuilder.setPath(destinationPath);
            return urlBuilder.buildURL();
        } catch (final MalformedURLException e) {
            return "http://localhost:8080" + destinationPath;
        }
    }

    @Nonnull public final static String IDP_ENTITY_ID = "https://idp.example.org";

    /** The SP entity ID. */
    @Nonnull public final static String SP_ENTITY_ID = "https://sp.example.org";

    @Qualifier("test.sp.Credential") @Autowired protected Credential spCredential;

    public MessageContext buildOutboundMessageContext(AuthnRequest authnRequest, String bindingUri) {
        final MessageContext messageContext = new MessageContext();
        messageContext.setMessage(authnRequest);

        SAMLPeerEntityContext peerContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        peerContext.setEntityId(IDP_ENTITY_ID);

        SAMLEndpointContext endpointContext = peerContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(buildIdpSsoEndpoint(bindingUri, authnRequest.getDestination()));

        SignatureSigningParameters signingParameters = new SignatureSigningParameters();
        signingParameters.setSigningCredential(spCredential);
        SecurityParametersContext secParamsContext =
            messageContext.getSubcontext(SecurityParametersContext.class, true);
        secParamsContext.setSignatureSigningParameters(signingParameters);

        return messageContext;
    }

    public SingleSignOnService buildIdpSsoEndpoint(String binding, String destination) {
        SingleSignOnService ssoEndpoint =
            (SingleSignOnService) builderFactory.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME).buildObject(
                SingleSignOnService.DEFAULT_ELEMENT_NAME);
        ssoEndpoint.setBinding(binding);
        ssoEndpoint.setLocation(destination);
        return ssoEndpoint;
    }

    static XMLObjectBuilderFactory builderFactory ;

    static {
        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException(e);
        }
        XMLObjectProviderRegistrySupport.getParserPool();
        builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        XMLObjectProviderRegistrySupport.getMarshallerFactory();
        XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    }

    public AuthnRequest buildAuthnRequest(final HttpServletRequest servletRequest) throws EncryptionException {
        return buildAuthnRequest(servletRequest, getAcsUrl(servletRequest), SAMLConstants.SAML2_POST_BINDING_URI);
    }

    public String getAcsUrl(final HttpServletRequest servletRequest) {
        return getAcsUrl(servletRequest, "/sp/SAML2/POST/ACS");
    }

    public String getAcsUrl(final HttpServletRequest servletRequest, final String acsURL) {
        // TODO servlet context
        String baseUrl = getBaseUrl(servletRequest);
        try {
            URLBuilder urlBuilder = new URLBuilder(SimpleURLCanonicalizer.canonicalize(baseUrl));
            urlBuilder.setPath(acsURL);
            return urlBuilder.buildURL();
        } catch (MalformedURLException e) {
            return "http://localhost:8080" + acsURL;
        }
    }

    public String getBaseUrl(HttpServletRequest servletRequest) {
        // TODO servlet context
        String requestUrl = servletRequest.getRequestURL().toString();
        try {
            URLBuilder urlBuilder = new URLBuilder(requestUrl);
            urlBuilder.setUsername(null);
            urlBuilder.setPassword(null);
            urlBuilder.setPath(null);
            urlBuilder.getQueryParams().clear();
            urlBuilder.setFragment(null);
            return urlBuilder.buildURL();
        } catch (MalformedURLException e) {
            return "http://localhost:8080";
        }

    }

    protected IdentifierGenerationStrategy idGenerator = new Type4UUIDIdentifierGenerationStrategy();

    public AuthnRequest buildAuthnRequest(final HttpServletRequest servletRequest, final String acsURL, final String outboundBinding)
        throws EncryptionException {
        final AuthnRequest authnRequest =
            (AuthnRequest) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME).buildObject(
                AuthnRequest.DEFAULT_ELEMENT_NAME);

        authnRequest.setID(idGenerator.generateIdentifier());
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setAssertionConsumerServiceURL(acsURL);
        authnRequest.setProtocolBinding(outboundBinding);

        final Issuer issuer =
            (Issuer) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)
                .buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(SP_ENTITY_ID);
        authnRequest.setIssuer(issuer);

        final NameIDPolicy nameIDPolicy =
            (NameIDPolicy) builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME).buildObject(
                NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIDPolicy.setAllowCreate(true);
        authnRequest.setNameIDPolicy(nameIDPolicy);

//        final NameID nameID =
//            (NameID) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)
//                .buildObject(NameID.DEFAULT_ELEMENT_NAME);
//        nameID.setValue("chao.wang");
//
//        final Subject subject =
//            (Subject) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME).buildObject(
//                Subject.DEFAULT_ELEMENT_NAME);
//        subject.setEncryptedID(getEncrypter().encrypt(nameID));
//        authnRequest.setSubject(subject);

        final RequestedAuthnContext reqAC =
            (RequestedAuthnContext) builderFactory.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME).buildObject(
                RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        final AuthnContextClassRef ac =
            (AuthnContextClassRef) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME).buildObject(
                AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        ac.setURI(AuthnContext.UNSPECIFIED_AUTHN_CTX);
        reqAC.getAuthnContextClassRefs().add(ac);
        authnRequest.setRequestedAuthnContext(reqAC);

        return authnRequest;
    }

    @Qualifier("test.idp.Credential") @Autowired protected Credential idpCredential;

    public Encrypter getEncrypter() {
        final DataEncryptionParameters encParams = new DataEncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
        final KeyEncryptionParameters kencParams = new KeyEncryptionParameters();
        kencParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        kencParams.setEncryptionCredential(idpCredential);
        final X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
        generator.setEmitEntityCertificate(true);
        kencParams.setKeyInfoGenerator(generator.newInstance());
        final Encrypter encrypter = new Encrypter(encParams, kencParams);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);
        return encrypter;
    }

}
