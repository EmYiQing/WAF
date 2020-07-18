package com.example.waf.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * 测试Controller
 */
@RestController
public class TestController {
    @RequestMapping(method = RequestMethod.GET, path = "/test")
    public String test() {
        return "<h1>Welcome To WAF!</h1>";
    }
}
