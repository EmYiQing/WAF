package com.example.waf.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

/**
 * 排列组合算法
 */
public class Algorithm {

    private static Stack<String> stack = new Stack<>();
    private static List<Object[]> result = new ArrayList<>();

    public static List<String[]> generateList(String[] arr, int target) {
        generate(arr, target, 0);
        List<String[]> list = new ArrayList<>();
        for (Object[] objects : result) {
            String[] temp = new String[target];
            for (int i = 0; i < objects.length; i++) {
                temp[i] = (String) objects[i];
            }
            list.add(temp);
        }
        return list;
    }

    private static void generate(String[] arr, int target, int cur) {
        if (cur == target) {
            Object[] temp = stack.toArray();
            result.add(temp);
            return;
        }

        for (String anArr : arr) {
            if (!stack.contains(anArr)) {
                stack.add(anArr);
                generate(arr, target, cur + 1);
                stack.pop();
            }

        }
    }

}
