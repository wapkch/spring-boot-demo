package com.spring.boot.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/hello")
    public String hello() throws InterruptedException {
        Thread.sleep(8000);
        return "hello";
    }

}
