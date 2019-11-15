package com.qualys.plugins.vm.webhook;

import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.logging.Logger;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.lang.StringUtils;
import com.qualys.plugins.vm.model.ProxyConfiguration;
import jenkins.model.Jenkins;

public class Webhook {
	private PrintStream buildLogger;
	private final String url;
    private final String data;
    private final ProxyConfiguration proxy;
    
    private static final int timeout = 60;
    private static final int RETRIES = 1;
    private final static Logger logger = Logger.getLogger(Webhook.class.getName());

    public Webhook(String url, String data, PrintStream logger, ProxyConfiguration proxy) {
        this.url = url;
        this.data = data;
        this.buildLogger = logger;
        this.proxy = proxy;
    }
    
    private HttpClient getHttpClient() {
        HttpClient client = new HttpClient();
        Jenkins jen = Jenkins.getInstance();
        if (jen != null) {
            if (proxy.getUseProxy()) {
                client.getHostConfiguration().setProxy(proxy.getProxyServer(), proxy.getProxyPort());
                String username = proxy.getProxyUsername();
                String password = proxy.getProxyPassword();
                // Consider it to be passed if username specified.
                if (StringUtils.isNotBlank(username)) {
                    client.getState().setProxyCredentials(AuthScope.ANY,
                            new UsernamePasswordCredentials(username, password));
                }
            }
        }
        return client;
    }
    
    public void post() {
        int tried = 0;
        boolean success = false;
        HttpClient client = getHttpClient();
        client.getParams().setConnectionManagerTimeout(timeout);
        String log = " Posting scan results to configured webhook URL - " + url;
        logger.info(log);
        buildLogger.println(new Timestamp(System.currentTimeMillis()) + log);        
        do {
            tried++;
            RequestEntity requestEntity;
            try {
                // uncomment to log what message has been sent
//                 logger.info("Posted JSON: " + data);
                requestEntity = new StringRequestEntity(data, "application/json", StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
            	for (StackTraceElement traceElement : e.getStackTrace())
                    logger.info("\tat " + traceElement); 
                break;
            }

            PostMethod post = new PostMethod(url);
            try {
                post.setRequestEntity(requestEntity);
                int responseCode = client.executeMethod(post);
                if (responseCode != HttpStatus.SC_OK) {
                    String response = post.getResponseBodyAsString();
                    String logg = " Posting data to " + url + " may have failed. Webhook responded with status code - " + responseCode;
                    buildLogger.println(new Timestamp(System.currentTimeMillis()) + logg);
                    logger.info(logg + "\nMessage from webhook - "+ response);
                } else {
                    success = true;
                }
            } catch (IOException e) {
            	String error = " Failed to post data to webhook URL - " + url;
            	buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
            	logger.info(error);
            	for (StackTraceElement traceElement : e.getStackTrace())
	                logger.info("\tat " + traceElement);
            } finally {
                post.releaseConnection();
            }
        } while (tried < RETRIES && !success);
        if(success) {
        	String log1 = "Successfully posted data to webhook URL - " + url;
        	buildLogger.println(new Timestamp(System.currentTimeMillis()) + log1);
        	logger.info(log1);
        }
    } // end of post method
} // end of Webhook class 
