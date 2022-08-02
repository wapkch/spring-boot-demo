package com.spring.boot.demo;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
//import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.springframework.webflow.executor.FlowExecutor;
import org.springframework.webflow.test.MockExternalContext;

//@RefreshScope
@RestController
public class DemoController {

    @Value("${name:joe}")
    private String name;

    @Autowired
    private FlowExecutor flowExecutor;

    @GetMapping("/hello")
    public String hello(HttpServletRequest request) throws InterruptedException {
        FlowExecutionResult flowExecutionResult =
            flowExecutor.launchExecution("SAML2/Redirect/SSO", null, new MockExternalContext());

        String xForwardedFor = request.getHeader("X-Forwarded-For");
        System.out.println("xForwardedFor: " + xForwardedFor);
        String nginxHeader = request.getHeader("X-Real-IP");
        System.out.println("xRealIp: " + nginxHeader);
        String remoteAddr = request.getRemoteAddr();
        System.out.println("remoteAddr: " + remoteAddr);

        return "hello: " + name;
    }

    @PostMapping
    public String post(HttpServletRequest request) throws IOException {
        int contentLength = request.getContentLength();
        byte[] bytes = new byte[contentLength];
        ServletInputStream inputStream = request.getInputStream();
        inputStream.read(bytes, 0, contentLength);
        System.out.println(bytes.toString());

        return "map.toString()";
    }

    public static void main(String[] args) {
        ExpressionParser expressionParser = new SpelExpressionParser();
        Expression expression = expressionParser.parseExpression("'#oauth2.throwOnError(hasAuthority('xyz') or hasAuthority('cathy'))'");
        String result = (String) expression.getValue();
    }

}

