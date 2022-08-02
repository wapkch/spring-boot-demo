//package com.spring.boot.demo;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.webflow.config.AbstractFlowConfiguration;
//import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
//import org.springframework.webflow.executor.FlowExecutor;
//
//@Configuration
//public class WebFlowConfig extends AbstractFlowConfiguration {
//
//    @Autowired
//    private SharedConfig sharedConfig;
//
//    @Bean
//    public FlowDefinitionRegistry flowRegistry() {
//        return getFlowDefinitionRegistryBuilder()
////            .setParent(sharedConfig.sharedFlowRegistry())
//            .setBasePath("classpath:/system/conf")
//            .addFlowLocation("/sso-redirect-flow.xml", "SAML2/Redirect/SSO")
//            .addFlowLocation("/sso-abstract-flow.xml", "saml2.sso.abstract")
//            .addFlowLocation("/saml-abstract-flow.xml", "saml.abstract")
//            .addFlowLocation("/authn-flow.xml", "authn")
//            .addFlowLocation("/password-authn-flow.xml", "authn/Password")
//            .addFlowLocation("/subject-c14n-flow.xml", "c14n")
//            .build();
//    }
//
//    @Bean
//    public FlowExecutor flowExecutor() {
//        return getFlowExecutorBuilder(flowRegistry()).build();
//    }
//
//
//    @Configuration
//    public static class SharedConfig extends AbstractFlowConfiguration {
//
//        @Bean
//        public FlowDefinitionRegistry sharedFlowRegistry() {
//            return getFlowDefinitionRegistryBuilder()
//                .addFlowLocation("classpath:/system/conf/sso-abstract-flow.xml", "saml2.sso.abstract")
//                .build();
//        }
//    }
//
////    @Bean
////    public FlowBuilderServices flowBuilderServices() {
////        return getFlowBuilderServicesBuilder()
////            .setViewFactoryCreator(mvcViewFactoryCreator())
////            .setDevelopmentMode(true).build();
////    }
//
//}
