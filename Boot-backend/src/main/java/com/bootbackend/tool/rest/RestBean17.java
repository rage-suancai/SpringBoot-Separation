package com.bootbackend.tool.rest;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

public record RestBean17<T> (int code, T data, String message) {

    public static <T> RestBean17<T> success(T data) {
        return new RestBean17<>(200, data, "请求成功");
    }

    public static <T> RestBean17<T> failure(int code, String message) {
        return new RestBean17<>(code, null, message);
    }

    public static <T> RestBean17<T> failure(int code) {
        return failure(code, "请求失败");
    }

    public String asJsonString() {
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }

}
