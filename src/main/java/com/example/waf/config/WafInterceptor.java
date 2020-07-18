package com.example.waf.config;

import com.example.waf.core.SqlInjectWAF;
import com.example.waf.utils.LEVEL;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 拦截器的一些配置
 */
@Component
public class WafInterceptor implements HandlerInterceptor {

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {
        String level = LEVEL.LOW_LEVEL;
        SqlInjectWAF sql_inject_waf = new SqlInjectWAF(level, request);
        if (sql_inject_waf.existSqlInject()) {
            // 检测到SQL注入，返回报错页面
            response.getWriter().write("<h1><font color=\"#FF0000\"> WAF : Firewall Detected Hacker!</font></h1>");
            return false;
        } else {
            return true;
        }

    }

    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                           Object handler, @Nullable ModelAndView modelAndView) throws Exception {
    }

    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, @Nullable Exception ex) throws Exception {
    }
}
