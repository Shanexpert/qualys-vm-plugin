package com.qualys.plugins.vm.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.commons.io.FileUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qualys.plugins.vm.auth.QualysAuth;
import com.qualys.plugins.vm.client.QualysVMClient;
import hudson.util.ListBoxModel.Option;
import org.apache.commons.lang.StringUtils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import hudson.EnvVars;
import hudson.model.Item;
import hudson.slaves.EnvironmentVariablesNodeProperty;
import hudson.slaves.NodeProperty;
import hudson.slaves.NodePropertyDescriptor;
import hudson.util.DescribableList;
import jenkins.model.Jenkins;

public class Helper {	
	private final static String CVE_REGEX = "CVE-\\d{4}-\\d{4,7}";
    private final static Logger logger = Logger.getLogger(Helper.class.getName());
    
    public QualysVMClient getClient(boolean useProxy, String server, String credsId, String proxyServer, int proxyPortInt, String proxyCredentialsId, Item item) {
    	QualysAuth auth = new QualysAuth();
    	
    	try{
			auth = getQualysAuth(useProxy, server, credsId, proxyServer,
					proxyPortInt, proxyCredentialsId, item);
    	}catch (Exception e) {
    		logger.info("Exception while getting Client. Error: " + e.getMessage());    		 
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    	}
    	return new QualysVMClient(auth, System.out);
    }
    
    public QualysAuth getQualysAuth(boolean useProxy, String server, String credsId, String proxyServer, int proxyPortInt, String proxyCredentialsId, Item item) {
    	QualysAuth auth = new QualysAuth();
    	String user = null, pass = null, proxyUser = null, proxyPass = null;
    	try{
			ArrayList<String> cred = getCredentails(credsId, item);
			if(cred != null && !cred.isEmpty()) {
				user = cred.get(0);
				pass = cred.get(1);
			}			
	    	auth.setQualysCredentials(server, user, pass);
	    	
	    	if(useProxy) {
				ArrayList<String> proxCreds = getCredentails(proxyCredentialsId, item);				
				if(proxCreds != null && !proxCreds.isEmpty()) {
					proxyUser = proxCreds.get(0);
					proxyPass = proxCreds.get(1);					
				} 
				auth.setProxyCredentials(proxyServer, proxyPortInt, proxyUser, proxyPass, useProxy);
	    	}
    	}catch (Exception e) {
    		logger.info("Exception while getting Qualys auth. Error: " + e.getMessage());    		 
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    	}
    	return auth;
    }
    
    public ArrayList<String> getCredentails(String credentialsId, Item item) {
    	ArrayList<String> list = new ArrayList<String>();
    	try {
	    	if (StringUtils.isNotEmpty(credentialsId)) {
	
	            StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
	                            StandardUsernamePasswordCredentials.class,
	                            item,
	                            null,
	                            Collections.<DomainRequirement>emptyList()),
	                    CredentialsMatchers.withId(credentialsId));            
	            list.add((c != null ? c.getUsername() : ""));
	            list.add((c != null ? c.getPassword().getPlainText() : ""));
	        }
    	}catch (Exception e) {
    		logger.info("Exception while getting Credentails. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);    		
    	}
    	return list;
    }
    
    public static boolean isValidCVEList(String cveList) {
    	if(cveList != null && !StringUtils.isBlank(cveList)) {    		
    		cveList = cveList.replace(" ", "");    		
    		List<String> cves = Arrays.asList(cveList.split(","));
    		Pattern patt = Pattern.compile(CVE_REGEX);
    		for(String el: cves) {
                Matcher matcher = patt.matcher(el);
                if (!(matcher.matches())) {
                    return false;
                }
    		}
    	}
    	return true;
    }
    
    public static boolean isValidQidList(String qidList) {
    	int qid = 0;
    	if(qidList != null && !StringUtils.isBlank(qidList)) {    		
    		qidList = qidList.replace(" ", "");    		
    		String[] qidL = qidList.split(",");
    		for(String q: qidL) {
    			if (q.contains("-")) {
    				String[] range = q.split("-");
    				int firstInRange = Integer.parseInt(range[0].trim());
    				int lastInRange = Integer.parseInt(range[1].trim());    				
    				if (firstInRange > lastInRange) {return false;}
    			} else {
	    			qid = Integer.parseInt(q);
	                if (qid < 0 ) {
	                    return false;
	                }
                }
    		}
    	}
    	return true;
    }
    
	public static String secondsToReadableTime(long duration){
	    long days = TimeUnit.SECONDS.toDays(duration);
	    duration -= TimeUnit.DAYS.toSeconds(days);

	    long hours = TimeUnit.SECONDS.toHours(duration);
	    duration -= TimeUnit.HOURS.toSeconds(hours);

	    long minutes = TimeUnit.SECONDS.toMinutes(duration);
	    duration -= TimeUnit.MINUTES.toSeconds(minutes);

	    long seconds = TimeUnit.SECONDS.toSeconds(duration);

	    StringBuilder msg = new StringBuilder( );
	    if (days!=0) {
	        msg.append( days+"day(s) ");
	    }
	    if (hours!=0) {
	        msg.append( hours+" hr ");
	    }
	    if (minutes!=0) {
	        msg.append( minutes+" min ");
	    }
	    if (seconds!=0) {
	        msg.append( seconds+" s ");
	    }
	    return msg.toString();
	}
	
	public static Object execXPath(String xml, String xPath, QName type) throws ParserConfigurationException {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
        	factory.setValidating(false); 
        	factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);        
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder
                    .parse(new InputSource(new StringReader(xml)));
            return execXPath(doc, xPath, type);
        } catch (ParserConfigurationException ex) {
        	logger.info("ParserConfigurationException in extracting Xpath of xml String. Reason: " + ex.getMessage()+ "\n");
        	for (StackTraceElement traceElement : ex.getStackTrace())
                logger.info("\tat " + traceElement);			 
        } catch (Exception e) {
        	logger.info("Exception in extracting Xpath of xml String. Reason: " + e.getMessage());
        	for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);        	
        }
        return null;
    }
    public static Object execXPath(Node node, String xPath, QName type) {

        XPath xpath = XPathFactory.newInstance().newXPath();

        Object object = null;
        try {
            object = xpath.evaluate(xPath, node, type);
        } catch (XPathExpressionException e) {
        	logger.info("Exception in extracting Xpath of Node. Error: " + e.getMessage());
        	for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);        	
        }
        return object;
    }
    
    public static Logger getLogger(String loggerName) {
    	Logger pluginLogger = Logger.getLogger(loggerName);
    	try {
    		pluginLogger.setUseParentHandlers(false);
	    	QualysLogFormatter formatter = new QualysLogFormatter();
	    	Handler handler = new ConsoleHandler();
	    	handler.setFormatter(formatter);
	    	pluginLogger.addHandler(handler);
    	} catch(Exception e) {
    		logger.info("Error while formatting logger, reason: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);    		
    	}
    	return pluginLogger;
    }
    
    public static class QualysLogFormatter extends Formatter {
        // Create a DateFormat to format the logger timestamp.
        private final DateFormat df = new SimpleDateFormat("MMM dd, yyyy hh:mm:ss a");

        public String format(LogRecord record) {
            StringBuilder builder = new StringBuilder(1000);
            builder.append(df.format(new Date(record.getMillis()))).append(" - ");
            builder.append("[").append(record.getSourceClassName()).append(".");
            builder.append(record.getSourceMethodName()).append("] - ");
            builder.append(record.getLevel()).append(": ");
            builder.append(formatMessage(record));
            builder.append("\n");
            return builder.toString();
        }

        public String getHead(Handler h) {
            return super.getHead(h);
        }

        public String getTail(Handler h) {
            return super.getTail(h);
        }
    }

	public static void createNewFile(String rootDir, String filename, String content, PrintStream buildLogger) {
  	  	   	
    	File f = new File(rootDir + File.separator + filename + ".json");
	    if(!f.getParentFile().exists()){
	        f.getParentFile().mkdirs();
	    }

	    if(!f.exists()){
	        try {
	            f.createNewFile();
	            logger.info("JSON file created: " + f.toString());
	        } catch (Exception e) {
	        	String error = " Failed creating file " + filename + ", reason =" + e.getMessage();
	            buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
	            logger.info(error);
	        }
	    }
	    try {
	        File dir = new File(f.getParentFile(), f.getName());
	        PrintWriter writer = new PrintWriter(dir);
	        writer.print(content);
	        writer.close();
	    } catch (FileNotFoundException e) {
	    	String error = " Failed writing file " + filename + ", reason =" + e.getMessage();
	    	buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
	    	logger.info(error);
	    	for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
	    }
    }
	
	private static Comparator<Option> OptionItemmsComparator = new Comparator<Option>() {
        @Override
        public int compare(Option e1, Option e2) {
            return e1.name.toLowerCase().compareTo(e2.name.toLowerCase());
        }
    };

	public static void copyEvaluationResultToFile(String rootDir, String filename, PrintStream buildLogger,	JsonObject evalresult) throws IOException {
		Gson gson = new Gson();
		File f = new File(rootDir + File.separator + filename + ".json");
		
		if(f.exists()){
			createGlEnVar("RESULT_FILENAME",f.toString()); // Create a Jenkins environment variable RESULT_FILENAME
    		String contentStr = FileUtils.readFileToString(f);
    		JsonObject respObj = gson.fromJson(contentStr, JsonObject.class);
    		
    		GsonBuilder builder = new GsonBuilder();
			gson = builder.serializeNulls().create(); // for null values
			
			String sevVulnsJson = gson.toJson(evalresult);
			JsonElement sevVulnsElement = gson.fromJson(sevVulnsJson, JsonElement.class);
    		respObj.add("evaluationResult", sevVulnsElement);
    		String final_content = gson.toJson(respObj);
    		try {
    	        File dir = new File(f.getParentFile(), f.getName());
    	        PrintWriter writer = new PrintWriter(dir);
    	        writer.print(final_content);
    	        writer.close();
    	    } catch (FileNotFoundException e) {
    	    	String error = " Failed writing to file " + filename + ", reason =" + e.getMessage(); 
    	    	logger.info(error);
    	    	buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
    	    }
    	}		
	} // end of copyEvaluationResultToFile method
	
	public static String urlEncodeUTF8(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
        	for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
            throw new UnsupportedOperationException(e);
        }
    }// End of urlEncodeUTF8
	
    public static String urlEncodeUTF8(JsonObject map) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<?,?> entry : map.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(String.format("%s=%s",
                urlEncodeUTF8(entry.getKey().toString()),
                urlEncodeUTF8(entry.getValue().toString())
            ));
        }
        return sb.toString();       
    }// End of urlEncodeUTF8
    
    public static String intListToString(ArrayList<Integer> numbers) {
		if (!numbers.isEmpty()) {
		   StringBuilder buffer = new StringBuilder();
		   for (Integer nextN : numbers) {
		       buffer.append(nextN).append(" ");
		   }
		   return buffer.toString();
		} else {
			return "";
		}
	}// listToString(List<Integer> numbers)
    
    public static String stringListToString(ArrayList<String> strings) {
		if (!strings.isEmpty()) {
		   StringBuilder buffer = new StringBuilder();
		   for (String nextS : strings) {
		       buffer.append(nextS).append(", ");
		   }
		   return buffer.toString();
		}else {
			return "";
		}
	}// listToString(List<Integer> numbers)
    
    //create Global Environment Variables
    public static void createGlEnVar(String key, String value) throws IOException{
    	try {
	        Jenkins instance = Jenkins.getInstance();
	
	        DescribableList<NodeProperty<?>, NodePropertyDescriptor> globalNodeProperties = instance.getGlobalNodeProperties();
	        List<EnvironmentVariablesNodeProperty> envVarsNodePropertyList = globalNodeProperties.getAll(EnvironmentVariablesNodeProperty.class);
	
	        EnvironmentVariablesNodeProperty newEnvVarsNodeProperty = null;
	        EnvVars envVars = null;
	
	        if ( envVarsNodePropertyList == null || envVarsNodePropertyList.size() == 0 ) {
	            newEnvVarsNodeProperty = new hudson.slaves.EnvironmentVariablesNodeProperty();
	            globalNodeProperties.add(newEnvVarsNodeProperty);
	            envVars = newEnvVarsNodeProperty.getEnvVars();
	        } else {
	            envVars = envVarsNodePropertyList.get(0).getEnvVars();
	        }
	        envVars.put(key, value);
	        logger.info(envVars.toString());
	        instance.save();
    	} catch(Exception e) {
    		logger.info("Exception while getting Global Environment Variables. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);    		
    	}
    }// end of createGlEnVar method
    
    public static String longToTime(long millis) {
    	return String.format("%02d:%02d:%02d", 
    			TimeUnit.MILLISECONDS.toHours(millis),
    			TimeUnit.MILLISECONDS.toMinutes(millis) -  
    			TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(millis)), // The change is in this line
    			TimeUnit.MILLISECONDS.toSeconds(millis) - 
    			TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(millis))); 
    }// end of longToTime method
    
    public static JsonObject removeBigData(JsonObject respObj) {
    	JsonArray arrTemp = new JsonArray();
    	JsonArray arr = null;
    	JsonObject scanObject = new JsonObject();
    	try {
    		if(respObj == null || !respObj.has("data")) {
    			String[] summaryAttrs = {"launch_date", "type", "duration", "network"};    			
   				for(int i = 0; i<summaryAttrs.length; i++) {   					
					scanObject.addProperty(summaryAttrs[i], "");					
   				}
   				JsonElement jelement = new JsonParser().parse(scanObject.toString());  				  				
   				arrTemp.add(jelement);
   				respObj = new JsonObject();
   			}else {
				arr = respObj.getAsJsonArray("data");			
				for (JsonElement s: arr) {   					
					scanObject = s.getAsJsonObject();
					scanObject.remove("results");
					scanObject.remove("threat");
					scanObject.remove("impact");
					scanObject.remove("solution");
					scanObject.remove("exploitability");
					scanObject.remove("associated_malware");
					scanObject.remove("os_cpe");
					if (scanObject.has("qid") && scanObject.has("type") && (scanObject.get("type").getAsString().equalsIgnoreCase("Vuln") || scanObject.get("type").getAsString().equalsIgnoreCase("Practice"))) {
						if (scanObject.get("type").getAsString().equalsIgnoreCase("Vuln")) scanObject.addProperty("type", "Confirmed");
						if (scanObject.get("type").getAsString().equalsIgnoreCase("Practice")) scanObject.addProperty("type", "Potential");  						
						arrTemp.add(s);   						
					}// End of if
				}// End of for
			}
			respObj.add("data", arrTemp);			
    	}catch (Exception e) {
    		logger.info("Exception while removing Big Data key:value fields. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);    		    		
    	}
    	return respObj;
    }// end of removeBigData

	/**
	 * @return the optionItemmsComparator
	 */
	public static Comparator<Option> getOptionItemmsComparator() {
		return OptionItemmsComparator;
	}

	/**
	 * @param optionItemmsComparator the optionItemmsComparator to set
	 */
	public static void setOptionItemmsComparator(Comparator<Option> optionItemmsComparator) {
		OptionItemmsComparator = optionItemmsComparator;
	}
}// end of Helper class