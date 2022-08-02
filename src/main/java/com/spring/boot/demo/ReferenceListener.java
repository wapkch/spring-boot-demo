package com.spring.boot.demo;

import java.util.Properties;

import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertiesPropertySource;

import net.shibboleth.ext.spring.config.BooleanToPredicateConverter;
import net.shibboleth.ext.spring.config.FunctionToFunctionConverter;
import net.shibboleth.ext.spring.config.PredicateToPredicateConverter;
import net.shibboleth.ext.spring.config.StringBooleanToPredicateConverter;
import net.shibboleth.ext.spring.config.StringToDurationConverter;
import net.shibboleth.ext.spring.config.StringToIPRangeConverter;
import net.shibboleth.ext.spring.config.StringToPeriodConverter;
import net.shibboleth.ext.spring.config.StringToResourceConverter;

public class ReferenceListener implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        ConfigurableEnvironment environment = event.getEnvironment();

        if (environment != null) {
            ConfigurableConversionService conversionService = environment.getConversionService();
            conversionService.addConverter(new StringToIPRangeConverter());
            conversionService.addConverter(new BooleanToPredicateConverter());
            conversionService.addConverter(new StringBooleanToPredicateConverter());
            conversionService.addConverter(new StringToResourceConverter());
            conversionService.addConverter(new FunctionToFunctionConverter());
            conversionService.addConverter(new PredicateToPredicateConverter());
            conversionService.addConverter(new StringToDurationConverter());
            conversionService.addConverter(new StringToPeriodConverter());
        }
    }

}
