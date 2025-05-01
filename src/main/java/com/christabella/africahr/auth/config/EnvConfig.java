package com.christabella.africahr.auth.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;


@Configuration
@PropertySource("classpath:application.properties")
@PropertySource(value = "file:.env", ignoreResourceNotFound = true)
public class EnvConfig {
}
