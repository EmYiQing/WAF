package com.example.waf.core;

import com.example.waf.utils.Algorithm;
import com.example.waf.utils.LEVEL;

import javax.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.util.*;

/**
 * SQL注入WAF
 */
public class SqlInjectWAF {

    private static final String[] HIGH_KEY_WORD = {"union", "select", "order", "information_schema", "1=1"};
    private static final String[] SPACE_KEY_WORD = {"%09", "%0a", "%0d", "%20", "%a0", "/**/", "+"};
    private static final String[] FUNCTIONS = {"database", "version", "user", "updatexml", "extractvalue", "floor"};

    private String level;
    private HttpServletRequest request;
    private Map<String, String> headers;
    private Map<String, String[]> params;
    private static List<String> lowLevelTargetList = null;

    /**
     * 构造方法
     *
     * @param level   安全级别
     * @param request HTTP请求
     */
    public SqlInjectWAF(String level, HttpServletRequest request) {
        this.request = request;
        this.level = level;

        Map<String, String> result = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            String value = request.getHeader(name);
            result.put(name, value);
        }
        this.headers = result;
        this.params = request.getParameterMap();

    }

    /**
     * 高安全级别的检测
     *
     * @return 是否存在SQL注入
     */
    private boolean doHighLevelDetect() {
        boolean flag1 = doDetectHeadersHigh();
        boolean flag2 = doDetectParamsHigh();
        return flag1 || flag2;
    }

    /**
     * 低安全级别的检测
     *
     * @return 是否存在SQL注入
     */
    private boolean doLowLevelDetect() {
        boolean flag1 = doDetectHeadersLow();
        boolean flag2 = doDetectParamsLow();
        return flag1 || flag2;
    }

    /**
     * 高安全级别检测参数
     *
     * @return 是否存在SQL注入
     */
    private boolean doDetectParamsHigh() {
        boolean flag;
        for (String name : params.keySet()) {
            for (String value : params.get(name)) {
                flag = detectKeyWordHigh(value);
                if (flag) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 低安全级别检测参数
     *
     * @return 是否存在SQL注入
     */
    private boolean doDetectParamsLow() {
        boolean flag;
        for (String name : params.keySet()) {
            for (String value : params.get(name)) {
                flag = detectKeyWordLow(value);
                if (flag) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 高安全级别检测请求头
     *
     * @return 是否存在SQL注入
     */
    private boolean doDetectHeadersHigh() {
        boolean flag = false;
        for (String name : headers.keySet()) {
            if (name.toLowerCase().equals("user-agent")) {
                flag = detectKeyWordHigh(headers.get(name));
            }
            if (name.toLowerCase().equals("cookie")) {
                flag = detectKeyWordHigh(headers.get(name));
            }
            if (name.toLowerCase().equals("referer")) {
                flag = detectKeyWordHigh(headers.get(name));
            }
        }
        return flag;
    }

    /**
     * 低安全级别检测请求头
     *
     * @return 是否存在SQL注入
     */
    private boolean doDetectHeadersLow() {
        boolean flag = false;
        for (String name : headers.keySet()) {
            if (name.toLowerCase().equals("user-agent")) {
                flag = detectKeyWordLow(headers.get(name));
            }
            if (name.toLowerCase().equals("cookie")) {
                flag = detectKeyWordLow(headers.get(name));
            }
            if (name.toLowerCase().equals("referer")) {
                flag = detectKeyWordLow(headers.get(name));
            }
        }
        return flag;
    }

    /**
     * 高安全级别检测请求头和参数的具体实现
     *
     * @return 是否存在SQL注入
     */
    private boolean detectKeyWordHigh(String key) {
        key = key.toLowerCase();
        for (String s : HIGH_KEY_WORD) {
            if (key.contains(s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 低安全级别检测请求头和参数的具体实现
     *
     * @return 是否存在SQL注入
     */
    private boolean detectKeyWordLow(String key) {
        key = key.toLowerCase();
        boolean flag = false;
        generateDict();
        if (key.contains("/*!") && key.contains("*/")) {
            flag = detectKeyWordHigh(key);
        }
        if (key.contains("--") || key.contains("--+") || key.contains("%23")) {
            int length = key.length();
            if (key.lastIndexOf("--") >= (length - 6) ||
                    key.lastIndexOf("--+") >= (length - 6) ||
                    key.lastIndexOf("#") >= (length - 6)) {
                flag = detectKeyWordHigh(key);
            }
        }
        for (String s : lowLevelTargetList) {
            s = URLDecoder.decode(s);
            if (key.contains(s)) {
                return true;
            }
        }
        return flag;
    }

    /**
     * 生成字典
     */
    private void generateDict() {
        if (lowLevelTargetList == null) {
            lowLevelTargetList = new ArrayList<>();
            //生成重复组合的列表
            for (String space : SPACE_KEY_WORD) {
                for (int i = 1; i <= 5; i++) {
                    StringBuilder newSpace = new StringBuilder();
                    for (int j = 1; j <= i; j++) {
                        newSpace.append(space);
                    }
                    lowLevelTargetList.add("union" + newSpace + "select");
                    lowLevelTargetList.add("order" + newSpace + "by");
                    lowLevelTargetList.add("and" + newSpace + "1=1");
                    lowLevelTargetList.add("or" + newSpace + "1=1");
                    for (String function : FUNCTIONS) {
                        lowLevelTargetList.add(function + newSpace + "()");
                    }
                }
            }
            //生成排列组合的列表
            for (int i = 0; i < 5; i++) {
                List<String[]> arr = Algorithm.generateList(SPACE_KEY_WORD, i);
                for (String[] a : arr) {
                    StringBuilder sb = new StringBuilder();
                    for (String b : a) {
                        sb.append(b);
                    }
                    lowLevelTargetList.add("union" + sb + "select");
                    lowLevelTargetList.add("order" + sb + "by");
                    lowLevelTargetList.add("and" + sb + "1=1");
                    lowLevelTargetList.add("or" + sb + "1=1");
                    for (String function : FUNCTIONS) {
                        lowLevelTargetList.add(function + sb + "()");
                    }
                }
            }
        }
    }

    /**
     * 对外暴漏接口
     *
     * @return 是否存在SQL注入
     */
    public boolean existSqlInject() {
        boolean exist = false;
        if (level.equals(LEVEL.HIGH_LEVEL)) {
            exist = doHighLevelDetect();
        } else if (level.equals(LEVEL.LOW_LEVEL)) {
            exist = doLowLevelDetect();
        }
        if (exist) {
            System.out.println("###############################################################");
            System.out.println("[WAF]" + " [" + new Date().toString() + "] [" + level + "] Detected SQL Inject");
            System.out.println("IP:" + request.getRemoteAddr() + "     Port:" + request.getRemotePort() + "\n");
        }
        return exist;
    }
}
