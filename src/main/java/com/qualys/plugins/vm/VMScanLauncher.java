/* This file is responsible for the execution of the Job Steps*/
package com.qualys.plugins.vm;

import java.io.PrintStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import com.google.gson.JsonObject;
import com.qualys.plugins.vm.auth.QualysAuth;
import com.qualys.plugins.vm.client.QualysVMClient;
import com.qualys.plugins.vm.client.QualysVMResponse;
import com.qualys.plugins.vm.criteria.QualysCriteria;
import com.qualys.plugins.vm.model.ProxyConfiguration;
import com.qualys.plugins.vm.report.ReportAction;
import com.qualys.plugins.vm.util.BuildFailedException;
import com.qualys.plugins.vm.util.Helper;
import com.qualys.plugins.vm.util.ScanErrorException;
import com.qualys.plugins.vm.util.TimeOutException;
import com.qualys.plugins.vm.webhook.Webhook;
import com.qualys.plugins.vm.webhook.WebhookCriteria;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.model.Run;
import hudson.model.TaskListener;
import com.google.gson.Gson;
import com.google.gson.JsonArray;

public class VMScanLauncher{
	private Map <String, String> scanMap = null;
	private Run<?, ?> run;
    private TaskListener listener;
    private PrintStream buildLogger;
    private String hostIp;
    private String scanTarget;
    private String ec2Id;
    private String ec2ConnName;
    private String ec2Endpoint;
    private String scannerName;
    private String scanName;
    private String scanNameResolved;
    private String optionProfile;
    private int pollingIntervalForVulns;
    private int vulnsTimeout;
    private String scanStatus = null;
    private String subScanStatus = "";
    private boolean useHost; 
    private boolean useEc2; 
    
    private QualysAuth auth;
    private String webhookUrl;
    private String byCvss;
    
    private boolean isFailConditionsConfigured;
    private JsonObject criteriaObject;
    private JsonObject WebhookData;
    
    private QualysVMClient apiClient;
	private String duration;
	private String reference;
	private String scanType;
	private JsonObject result = null;
	private boolean passed = true;
	private boolean hostNotAlive = false;	
    
    private final static Logger logger = Helper.getLogger(VMScanLauncher.class.getName());
    private final static int DEFAULT_POLLING_INTERVAL_FOR_VULNS = 2; //2 minutes
    private final static int DEFAULT_TIMEOUT_FOR_VULNS = 60; //1Hrs        
    
    public VMScanLauncher(Run<?, ?> run, TaskListener listener, String hostIp, String ec2Id, String ec2ConnName, 
    		String ec2Endpoint, String scannerName, String scanName, String optionProfile,  
    		boolean isFailConditionsConfigured, String pollingIntervalStr, String vulnsTimeoutStr, 
    		JsonObject criteriaObject, boolean useHost, boolean useEc2, QualysAuth auth,  
    		String webhookUrl, String byCvss) {
    	
    	this.run = run;
        this.listener = listener;
        this.buildLogger = listener.getLogger();
        this.useHost = useHost;
        this.hostIp = hostIp;
        this.scanName = scanName.trim();
        this.scannerName = scannerName;
        this.useEc2 = useEc2;
        this.ec2Id = ec2Id;
        this.ec2ConnName = ec2ConnName;
        this.ec2Endpoint = ec2Endpoint;
        this.optionProfile = optionProfile;   
        this.auth = auth;
        this.webhookUrl = webhookUrl;
        this.byCvss = byCvss;
        
        
        if(this.scanName != null && !this.scanName.isEmpty()) {
        	this.scanName += "_[timestamp]";
        }
        
        this.criteriaObject = criteriaObject;
        this.isFailConditionsConfigured = isFailConditionsConfigured;
        
    	this.apiClient = new QualysVMClient(this.auth, System.out);
        
        this.pollingIntervalForVulns = setTimeoutInMinutes("pollingInterval", DEFAULT_POLLING_INTERVAL_FOR_VULNS, pollingIntervalStr, listener);
		this.vulnsTimeout = setTimeoutInMinutes("vulnsTimeout", DEFAULT_TIMEOUT_FOR_VULNS, vulnsTimeoutStr, listener);
    } // end of Xtor
    
    private int setTimeoutInMinutes(String timeoutType, int defaultTimeoutInMins, String timeout, TaskListener listener) {    	   	
    	if (!(timeout == null || timeout.isEmpty()) ){
    		try {
    			//calculate the timeout in seconds
    			String[] numbers = timeout.split("\\*");
    			int timeoutInMins = 1;
    			for (int i = 0; i<numbers.length ; ++i) {
    				timeoutInMins *= Long.parseLong(numbers[i]);
    			}    			
    			return timeoutInMins;
    		} catch(Exception e) {
    			String error = " Invalid " + timeoutType + " time value. Cannot parse -"+e.getMessage() + "\n";
    			error = error + " Using default period of " + (timeoutType.equals("vulnsTimeout") ? "60" : defaultTimeoutInMins) + " minutes for " + timeoutType + ".";
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);    			
    			logger.info(error);    			
    		}
    	}
    	return defaultTimeoutInMins; 
    }
    
    /*This method is called in the launchHostScan method under VMScanNotifiers class*/
	public void getAndProcessLaunchScanResult() throws Exception {
    	try {
    		scanMap = launchScan();    		
    		String scanRef = scanMap.get("scanRef");
    		String scanId = scanMap.get("scanId");
    		if(scanRef != null && !scanRef.equals("") && scanId != null && !scanId.equals("")) {
	    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " New Scan launched successfully. Scan ID: " + scanId + " & Scan Reference: " + scanRef);	    		
				//evaluate for failure conditions
				JsonObject evaluationResult = null;
				Boolean buildPassed = true;	
				if(isFailConditionsConfigured) {
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Fail or exclude conditions are configured.");					
				} else {
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " No Fail or exclude conditions are configured.\n"+ new Timestamp(System.currentTimeMillis()) + " Build will finish after scan complete.");
				}
				//create status link on right side
	    		if(this.useHost)
	    		{
	    			this.scanTarget = this.hostIp;
	    		} else {
	    			this.scanTarget = this.ec2Id;
	    		}	    		
	    		ReportAction action = new ReportAction(run, scanRef, scanId, scanTarget, scannerName, 
	    				scanNameResolved, this.auth.getServer(), this.auth.getUsername(), 
	    				this.auth.getPassword().getPlainText(), this.auth.getUseProxy(), 
	    				this.auth.getProxyServer(), this.auth.getProxyPort(), 
	    				this.auth.getProxyUsername(), this.auth.getProxyPassword().getPlainText(), 
	    				duration, reference, scanType, scanStatus, subScanStatus);
				run.addAction(action);				
				
				result = fetchScanResult(scanRef);
				String scanRefNew = scanRef.replace("/","_");
				
				if(result != null) {
					if(!this.subScanStatus.equalsIgnoreCase("No_Host")) {
						evaluationResult = evaluateFailurePolicy(result);
						Helper.copyEvaluationResultToFile(run.getArtifactsDir().getAbsolutePath(), "qualys_" + scanRefNew, buildLogger, evaluationResult.getAsJsonObject("result"));						
						buildPassed = evaluationResult.get("passed").getAsBoolean();
					}else {
						logger.info("WARNING: The host is not alive!!!");
						buildLogger.println(new Timestamp(System.currentTimeMillis()) + " WARNING: The host is not alive!!!");
						Helper.copyEvaluationResultToFile(run.getArtifactsDir().getAbsolutePath(), "qualys_" + scanRefNew, buildLogger, new JsonObject());
						hostNotAlive = true;
						if(webhookUrl != null && !StringUtils.isEmpty(webhookUrl)) {sendToWebhook(evaluationResult);}
						throw new BuildFailedException("Scan Status: "+ scanStatus+ " | Sub Scan Status: "+ subScanStatus);
					}
				}
				if(isFailConditionsConfigured && !buildPassed) {
					String failureMessage = evaluationResult.get("failureMessage").getAsString();					 
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Build failed. The reason of failure:" + evaluationResult.get("failureReason").getAsString());
					if(webhookUrl != null && !StringUtils.isEmpty(webhookUrl)) {
						sendToWebhook(evaluationResult);
					}
					throw new BuildFailedException(failureMessage);					
				}else if(webhookUrl != null && !StringUtils.isEmpty(webhookUrl)) {sendToWebhook(evaluationResult);}
    		} else {
    			String errorCode = scanMap.get("errorCode");
    			String errorText = scanMap.get("errorText");
    			if(useHost) throw new BuildFailedException("API Error. Could not launch new scan."
    					+ "\nReason:\n\tAPI Error Code: " + errorCode + "\n\tAPI Error Message: " + errorText);
    			if(useEc2) throw new BuildFailedException("API Error. Could not launch new scan."
    					+ "\nReason:Could not find the provided instance ID with a given EC2 configuration. "
    					+ "The user might have provided the wrong instance/connector/scanner details. "
    					+ "Re-check EC2 details provided for the scan."
    					+ "\n\tAPI Error Code: " + errorCode + "\n\tAPI Error Message: " + errorText);
    		}
    	} catch (BuildFailedException e) {
    		throw e;
    	}catch (AbortException e) {
    		String error = " AbortException while getting and processing Launch Scan Result. " + e;
    		logger.info(error);
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
    		throw new Exception(e.getMessage());
    	} catch (Exception e) {
    		String error = " Exception while getting and processing Launch Scan Result. " + e;
    		logger.info(error);
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);    		
    		throw new Exception(e.getMessage());
    	}	   	
    }// End of getAndProcessLaunchScanResult method
		
	private String getBuildFailureMessages(JsonObject result) throws Exception {
    	List<String> failureMessages = new ArrayList<String>();
		// For QIDs
    	failureMessages.add(this.getFailureMessages(result,"qids"));    	
		
    	// For CVEs
    	failureMessages.add(this.getFailureMessages(result,"cveIds"));    	
    	
    	// For CVSS
    	failureMessages.add(this.getFailureMessages(result,"cvss_base"));
    	failureMessages.add(this.getFailureMessages(result,"cvss3_base"));
//    	failureMessages.add(this.getFailureMessages(result,"cvss_temporal"));    	
//    	failureMessages.add(this.getFailureMessages(result,"cvss3_temporal"));
		
    	// For PCI
    	failureMessages.add(this.getFailureMessages(result,"pci_vuln"));
    	
    	// For Severity
		String sevConfigured = "\n\tConfigured : ";
		String sevFound = "\n\tFound : ";
		boolean severityFailed = false;
		for(int i=1; i<=5; i++) {
    		if(result.has("severities") && result.get("severities") != null && !result.get("severities").isJsonNull()) {
    			JsonObject sevObj = result.get("severities").getAsJsonObject();
    			JsonObject severity = sevObj.get(""+i).getAsJsonObject();
    			if(severity.has("configured") && !severity.get("configured").isJsonNull() && severity.get("configured").getAsInt() != -1) {
	    			sevFound += "Severity"+ i +": "+ (severity.get("found").isJsonNull() ? 0 : severity.get("found").getAsString()) + ";";
	    			sevConfigured += "Severity"+ i +">="+ severity.get("configured").getAsString() + ";";
		    		boolean sevPass = severity.get("result").getAsBoolean();
		    		if(!sevPass) {
		    			severityFailed = true;
		    		}
    			}
    		}
		}
		if(severityFailed) {
			failureMessages.add("\nThe vulnerabilities count by severity exceeded one of the configured threshold value :" + sevConfigured + sevFound);
		}
		
		return StringUtils.join(failureMessages, " ");
	}// End of getBuildFailureMessages
	
	private String getFailureMessages(JsonObject result, String field) {
		String configured = "\n\tConfigured : ";
		String found = "\n\tFound : ";
		String failureMsg = new String();
		if(result.has(field) && result.get(field) != null && !result.get(field).isJsonNull()) {
    		JsonObject obj = result.get(field).getAsJsonObject();
    		boolean pass = obj.get("result").getAsBoolean();
    		if(!pass) {
    			found += obj.get("found").getAsString();
    			configured += obj.get("configured").getAsString();
    			failureMsg = "\n" + field.toUpperCase()+" configured in Failure Conditions were found in the scan result : " + configured + found ;
    		}
		}
		return failureMsg;
	} // End of getFailureMessages
	
	public JsonObject evaluateFailurePolicy(JsonObject result) throws Exception{
		Gson gson = new Gson();
		QualysCriteria criteria = null;
		JsonObject obj = new JsonObject();
		JsonObject failConditions = criteriaObject.get("failConditions").getAsJsonObject();		
		if (failConditions.has("severities") || failConditions.has("qids") || failConditions.has("cve_id") || failConditions.has("cvss_base") || failConditions.has("failByPci")) {
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Evaluating the Failure conditions with Scan result...");
		} 
		if (failConditions.has("excludeBy")){			
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Exclude list is provided. Will execute the given exclude criteria...");
		}
		if(isFailConditionsConfigured) {
			criteria = new QualysCriteria(gson.toJson(criteriaObject), true);
		}else {
			criteria = new QualysCriteria(gson.toJson(criteriaObject), false);
		}
		passed = criteria.evaluate(result);	
		if(failConditions.has("excludeBy")) {
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Size of response BEFORE exclude list: " + criteria.getSizeBeforeExclude() + "\n" + new Timestamp(System.currentTimeMillis()) + " Size of response AFTER exclude list (Information Gathered \"IG\" not considered): " + criteria.getSizeAfterExclude());			
		}		
		obj.add("passed", gson.toJsonTree(passed));
		obj.add("result", criteria.getReturnObject());		
		if(!passed) {
			String failureMessage = getBuildFailureMessages(criteria.getResult());
			ArrayList<String> failureReason = criteria.getBuildFailedReasons();
			obj.addProperty("failureMessage", failureMessage);
			obj.addProperty("failureReason", failureReason.toString());
		}
		return obj;
	}// End of evaluateFailurePolicy
	
	@SuppressWarnings("null")
	public JsonObject fetchScanResult(String scanIdRef) throws TimeOutException, Exception {
		long startTime = System.currentTimeMillis();
    	long vulnsTimeoutInMillis = TimeUnit.MINUTES.toMillis(vulnsTimeout);
    	long pollingInMillis = TimeUnit.MINUTES.toMillis(pollingIntervalForVulns);
    	
    	JsonObject scanResult = null;
    	String scanStatus = null;
    	try {
	    	while ((scanStatus = getScanFinishedStatus(scanIdRef)) == null) {	    		
	    		long endTime = System.currentTimeMillis();
	    		if ((endTime - startTime) > vulnsTimeoutInMillis) {
	    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Failed to get scan result; timeout of " + vulnsTimeout + " minutes reached.");    			
	    			throw new TimeOutException("Timeout reached.");	    			
	    		}	    		
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Waiting for " + pollingIntervalForVulns + " minute(s) before making next attempt for scanResult of Scan Reference:" + scanIdRef);
    			Thread.sleep(pollingInMillis);	    		
	    	}
	    	if (scanStatus != null && scanStatus.equalsIgnoreCase("error")) {
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " The scan(Scan Reference: "+scanIdRef+") is not completed due to an error.");
        		throw new ScanErrorException(new Timestamp(System.currentTimeMillis()) + " The scan(Scan Reference: "+scanIdRef+") is not completed due to an error.");
        	}
    	}
    	catch (TimeOutException e) {
    		String error = " Exception: Timeout reached.";
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
    		logger.info(error);
    		throw e;
    	}
    	catch (ScanErrorException e) {
    		String error = " Exception: The scan got into an ERROR. Please check the status of the scan on Qualys POD.";
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
    		logger.info(error);
    		throw e;
    	}
    	catch(Exception e) {
    		if(!scanIdRef.isEmpty()) {
    			Map<String, String> printMap = new HashMap<String, String>();
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " User Have Aborted!!\n" +new Timestamp(System.currentTimeMillis()) +" Cancelling the scan with Scan Reference: " + scanIdRef);
				try {
					QualysVMResponse response = apiClient.cancelVmScan(scanIdRef);    		
		    		Document result = response.getResponseXml();					
  					NodeList error = result.getElementsByTagName("RESPONSE");
  					for (int temp = 0; temp < error.getLength(); temp++) {
	        			Node nNode = error.item(temp);
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) { 
	        				Element eElement = (Element) nNode;	        				
	        				if (eElement.getElementsByTagName("CODE").getLength() != 0){
	        					printMap.put("errorCode", eElement.getElementsByTagName("CODE").item(0).getTextContent().trim());
	                       	} else{
	                       		printMap.put("errorCode", "No code returned.");
	                       	}
	                        if (eElement.getElementsByTagName("TEXT").getLength() != 0){
	                        	printMap.put("errorText", eElement.getElementsByTagName("TEXT").item(0).getTextContent().trim());
	                       	} else{
	                       		printMap.put("errorText", "No text returned");
	                       	}	        				
	        			}
	        		}
  					buildLogger.println(
  							"\tAPI Response Code: "+printMap.get("errorCode").toString()
  							+ "\n\tAPI Response Message: "+printMap.get("errorText").toString());
				} catch (Exception e1) {
					buildLogger.println(
							"\tAPI Response Code: "+printMap.get("errorCode").toString()
  							+ "\n\tAPI Response Message: "+printMap.get("errorText").toString());
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Error:" + e1.getMessage());
				}
       	 }else {
       		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Aborting the build, scan was not launched!");
       	 }
    		throw e;
    	}
    	
    	if (scanStatus.equalsIgnoreCase("finished")) {
    		Gson gson = new Gson();
    		scanResult = getScanResult(scanIdRef);
			String scanResultString = gson.toJson(scanResult);
			String scanIdNew = scanIdRef.replace("/","_");
			Helper.createNewFile(run.getArtifactsDir().getAbsolutePath(), "qualys_" + scanIdNew, scanResultString, buildLogger);
    	}
    	if (scanStatus.equalsIgnoreCase("canceled") && isFailConditionsConfigured) {
    		throw new Exception(new Timestamp(System.currentTimeMillis()) + " The scan(Scan Reference: "+ scanIdRef + ") has been canceled. Please check the status of the scan on Qualys POD.");
    	}
    	if (scanStatus.equalsIgnoreCase("error") && isFailConditionsConfigured) {
    		throw new Exception(new Timestamp(System.currentTimeMillis()) + " The scan(Scan Reference: "+scanIdRef+") is not completed due to an error. Please check the status of the scan on Qualys POD.");
    	}	
		return scanResult;
	} // end of fetchScanResult
	
	public JsonObject getScanResult(String scanIdRef) throws Exception {
		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Fetching scan result..");
		JsonObject scanResult = null;
		QualysVMResponse statusResponse = apiClient.getScanResult(scanIdRef);
		scanResult = statusResponse.getResponse();
		if(webhookUrl != null && !StringUtils.isEmpty(webhookUrl)) {			
			WebhookData = WebhookCriteria.getScanDataForWebhook(scanResult,subScanStatus,useEc2, ec2Id);
		}
		return scanResult;
	}// end of getScanResult
	
	public String getScanFinishedStatus(String scanIdRef) {		
		Document result = null;
		try {
			QualysVMResponse response = apiClient.vMScansList(scanIdRef);
			result = response.getResponseXml();    		
    		//parse result
   			Integer respCodeObj = response.getResponseCode();
   			if(respCodeObj == null || respCodeObj != 200 ) {
   				String error = response.getErrorMessage().toString();
   				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Error while fetching the scan result after scan launch. Server returned: " + error +". Please do retry after sometime.");
   				logger.info("Error while fetching the scan result after scan launch. Server returned: " + error +". Please do retry after sometime.");
   				throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Error while fetching the scan result after scan launch. Server returned: " + error +". Please do retry after sometime.");   				
   			}else {
   				NodeList scanList = result.getElementsByTagName("SCAN");
        		for (int temp = 0; temp < scanList.getLength(); temp++) {	        			
        			Node nNode = scanList.item(temp);
        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {        				
	                    Element eElement = (Element) nNode;
	                    if (eElement.getElementsByTagName("DURATION") !=null) {
	                    	this.duration = eElement.getElementsByTagName("DURATION").item(0).getTextContent().trim();	
	                    }
	                    if (eElement.getElementsByTagName("REF") !=null) {
	                    	this.reference = eElement.getElementsByTagName("REF").item(0).getTextContent().trim();	
	                    }
	                    if (eElement.getElementsByTagName("TYPE") !=null) {
	                    	this.scanType = eElement.getElementsByTagName("TYPE").item(0).getTextContent().trim();	
	                    }
	                    if (eElement.getElementsByTagName("STATE") !=null) {
	                    	this.scanStatus = eElement.getElementsByTagName("STATE").item(0).getTextContent().trim();	
	                    }
	                    if (eElement.getElementsByTagName("STATE").item(0).getTextContent().trim().equalsIgnoreCase("Finished")) {
	                    	if (eElement.getElementsByTagName("SUB_STATE").getLength() > 0 ) {
		                    	this.subScanStatus = eElement.getElementsByTagName("SUB_STATE").item(0).getTextContent().trim();	
		                    }else {
		                    	this.subScanStatus = "Scan Successful";
		                    }
	                    }
	                    
	            	} // End of if	                    
        		} // End of for 
        		
				if(scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled") || (scanStatus.equalsIgnoreCase("finished"))) {
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Scan Status: "+ scanStatus + " | Sub Scan Status: " + this.subScanStatus);
					logger.info("Scan Status: " + scanStatus + " | Sub Scan Status: " + this.subScanStatus);
				}else {
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Scan Status: "+ scanStatus);
					logger.info("Scan Status: " + scanStatus);
				}
   				return (scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled") || scanStatus.equalsIgnoreCase("finished")) ? scanStatus : null;
			}
		}catch(Exception e) {
			String error = " Exception in scanStatus. " + e.getMessage();
			logger.info(error);
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);						
		}
		return scanStatus;
	}// end of getScanFinishedStatus
    
	/*This method is called in getAndProcessLaunchScanResult*/
    public Map<String, String> launchScan() throws Exception {
    	String requestData = new String();
    	String printLine = " Calling Launch Scan API with Payload: ";
    	Document result = null;
    	JsonObject vmScan = new JsonObject();
    	Map<String, String> returnMap = new HashMap<String, String>();		
    	//format name : [Job_Name]_jenkins_build_[build_number]_[timestamp]
    	EnvVars env = run.getEnvironment(listener);
    	String job_name = env.get("JOB_NAME");
    	String build_no = env.get("BUILD_NUMBER");
    	String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss").format(new Date());    	
    	this.scanNameResolved = this.scanName.replaceAll("(?i)\\[job_name\\]", job_name).replaceAll("(?i)\\[build_number\\]", build_no).replaceAll("(?i)\\[timestamp\\]", timestamp);   		
    	
    	// required POST parameters - name, hostIp, etc
    	if(this.scanNameResolved == null || this.scanNameResolved.isEmpty()) {
    		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Scan Name - Required parameter to launch scan is missing.");
    	} else {
    		vmScan.addProperty("scan_title", this.scanNameResolved.trim());
    	} // End of this.scanNameResolved
    	
    	if(optionProfile != null && !optionProfile.isEmpty()) {    		
    		vmScan.addProperty("option_title", optionProfile);
    	} else {
    		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Option Profile - Required parameter to launch scan is missing.");        		
    	} // End of optionProfile if
    	
    	if(scannerName != null && !scannerName.isEmpty()) {
			vmScan.addProperty("iscanner_name", scannerName);
    	} else {
    		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Scanner Name - Required parameter to launch scan is missing.");        		
    	} // End of scannerName if
    	
    	if (useHost) {
    		if(hostIp != null && !hostIp.isEmpty()) {    			
    			vmScan.addProperty("ip", hostIp);
        	}else {
        		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Host IP - Required parameter to launch scan is missing.");        		
        	}    		   		
    	}// end of useHost if
    	
    	if (useEc2) {
    		if(ec2Id != null && !ec2Id.isEmpty()) {
    			vmScan.addProperty("ec2_instance_ids", ec2Id);
        	}else {
        		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " EC2 Instance ID - Required parameter to launch scan is missing.");        		
        	}
    		if(ec2ConnName != null && !ec2ConnName.isEmpty()) {    			
    			vmScan.addProperty("connector_name", ec2ConnName);
        	} else {
        		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " EC2 Connector Name - Required parameter to launch scan is missing.");
        	}
    		if(ec2Endpoint != null && !ec2Endpoint.isEmpty()) {    			
    			vmScan.addProperty("ec2_endpoint", ec2Endpoint);
        	} else {
        		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " EC2 Endpoint - Required parameter to launch scan is missing.");        		
        	}
    	}// end of useHost if
    	
    	try{    		
    		requestData = Helper.urlEncodeUTF8(vmScan);
    		String rData = requestData.replace("%22", "");
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + printLine + rData.toString());    		
    		
    		if(isFailConditionsConfigured) {
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Using build failure conditions configuration: " + criteriaObject);
    			logger.info("Using build failure conditions configuration: " + criteriaObject);
    		}else {
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " No failure conditions configuration.");
    			logger.info("No failure conditions configuration.");
    		}
    		if(this.webhookUrl != null && !StringUtils.isBlank(this.webhookUrl)) {
    			logger.info("Using Job Specific Webhook URL settings: " + this.webhookUrl);
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) +" Using Job Specific Webhook URL settings: " + this.webhookUrl);
    		} else {
    				logger.info("No webhook configured.");
    				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " No webhook configured.");
    		}
    		Thread.sleep(6000);
    		
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Launching scan now...");    		
    		QualysVMResponse response = apiClient.launchVmScan(rData);
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Making POST Request: " + response.getRequest());
    		if (response.getRequestBody() != null) buildLogger.println(new Timestamp(System.currentTimeMillis()) + " API POST request body: " + response.getRequestBody());
    		result = response.getResponseXml();
    		//parse result
   			Integer respCodeObj = response.getResponseCode();
   			logger.info("POST responseCode: " + respCodeObj.toString());
   			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " POST responseCode: " + respCodeObj.toString());
   			   			
   			if(respCodeObj == null || respCodeObj != 200 ) {
   				String error = response.getErrorMessage().toString();   				
   				logger.info("Server Response: " + error +". Please do retry after sometime.");
   				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Server Response: " + error +". Please do retry after sometime.");
   				throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Error while launching new scan. Server returned: " + error +". Please do retry after sometime.");
   			}else {
   				try {
   					if(result.getDocumentElement().getNodeName().equalsIgnoreCase("SIMPLE_RETURN")) {
	   					NodeList error = result.getElementsByTagName("RESPONSE");
	   					for (int temp = 0; temp < error.getLength(); temp++) {	        			
		        			Node nNode = error.item(temp);
		        			if (nNode.getNodeType() == Node.ELEMENT_NODE) { 
		        				Element eElement = (Element) nNode;	        				
		        				if (eElement.getElementsByTagName("CODE").getLength() != 0){
		                        	returnMap.put("errorCode", eElement.getElementsByTagName("CODE").item(0).getTextContent().trim());
		                       	} else{
		                       		returnMap.put("errorCode", null);
		                       	}
		                        if (eElement.getElementsByTagName("TEXT").getLength() != 0){
		                        	returnMap.put("errorText", eElement.getElementsByTagName("TEXT").item(0).getTextContent().trim());
		                       	} else{
		                       		returnMap.put("errorText", null);
		                       	}	        				
		        			}
		        		}
	   					NodeList applinaceList = result.getElementsByTagName("ITEM");
		        		for (int temp = 0; temp < applinaceList.getLength(); temp++) {	        			
		        			Node nNode = applinaceList.item(temp);
		        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {        				
			                    Element eElement = (Element) nNode;
			                    String key = eElement.getElementsByTagName("KEY").item(0).getTextContent();
			                    if (key.equalsIgnoreCase("REFERENCE")){		                    			                    	
			                    	returnMap.put("scanRef", eElement.getElementsByTagName("VALUE").item(0).getTextContent().trim());
			                   	} // End of Inner if
			                    if (key.equalsIgnoreCase("ID")){
			                    	returnMap.put("scanId", eElement.getElementsByTagName("VALUE").item(0).getTextContent().trim());
			                   	} // End of Inner if		                    
		        			} // End of Outer if
		        		} // End of for loop
   					} else if (result.getDocumentElement().getNodeName().equalsIgnoreCase("GENERIC_RETURN")) {
   						NodeList error = result.getElementsByTagName("GENERIC_RETURN");
	   					for (int temp = 0; temp < error.getLength(); temp++) {	        			
		        			Node nNode = error.item(temp);
		        			if (nNode.getNodeType() == Node.ELEMENT_NODE) { 
		        				Element eElement = (Element) nNode;		        					        				
		                        if (eElement.getElementsByTagName("RETURN").getLength() != 0){
		                        	returnMap.put("errorText", eElement.getElementsByTagName("RETURN").item(0).getTextContent().trim());
		                       	} else{
		                       		returnMap.put("errorText", null);
		                       	}
		                        NodeList e = eElement.getElementsByTagName("RETURN");		                        
		        				for (int t = 0; t < e.getLength(); t++) {	        			
				        			Node n = e.item(t);
				        			if (n.getNodeType() == Node.ELEMENT_NODE) { 
				        				Element ee = (Element) n;
				        				if (!ee.getAttribute("number").isEmpty()){
				                        	returnMap.put("errorCode", ee.getAttribute("number"));
				                       	} else{
				                       		returnMap.put("errorCode", null);
				                       	}
				        			}
				        		}	
		        			}
		        		}
   					}	   						
	   				return returnMap;
   				}catch (Exception e) {   					
   					throw e;
   		    	} 
   			} // end of else
    	}catch (AbortException e) {
			throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Process Aborted."); 
		}catch (Exception e) {
			logger.info("Exception while launching scan. Error: "+ e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		throw e;
    	} // end of catch
    } // End of LaunchScan method 

    private void sendToWebhook(JsonObject evaluationResult) {
		try {	        	        	
        	if (useHost){	        		
        		postWebhookData(hostIp, evaluationResult);
        	}else {	        		
        		postWebhookData(ec2Id, evaluationResult);
        	}	        
        } catch(Exception e) {
        	String error = " Failed to post data to webhook. Exception: " + e.getMessage();
        	logger.info(error);
        	buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
        	for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
        }
	}
    
    public void postWebhookData(String machine, JsonObject scanReportObj) {
    	String buildNo = "";
        String jobName = "";
        String jobUrl = "";
        try {
        	EnvVars env = run.getEnvironment(listener);
        	buildNo = env.get("BUILD_NUMBER");
        	jobName = env.get("JOB_NAME");
        	jobUrl = env.get("JOB_URL");          	
    	
	    	//Add reports link for all hostIp / ec2Id + webhook
	    	JsonObject webhookPostData = new JsonObject();
	    	webhookPostData.addProperty("buildNumber", buildNo);
	    	webhookPostData.addProperty("jobName", jobName);
	    	webhookPostData.addProperty("jobUrl", jobUrl);
	    	webhookPostData.addProperty("buildStatus", passed ? "Success" : "Failed");
	    	if(hostNotAlive) webhookPostData.addProperty("buildStatus", "Failed");
	    	Gson gson = new Gson();    	    	
	    	if(!passed) {    		
	    		JsonArray failReasonsArray = new JsonArray();
	        	JsonObject obj = WebhookCriteria.makeFailReasonObject(machine, scanReportObj.getAsJsonObject("result"), byCvss, useHost);
	        	failReasonsArray.add(obj);
	    		webhookPostData.add("failReason", gson.toJsonTree(failReasonsArray));
	    	}
	    	ProxyConfiguration proxyConfiguration = new ProxyConfiguration(auth.getUseProxy(), auth.getProxyServer(), auth.getProxyPort(), auth.getProxyUsername(), auth.getProxyPassword()); 
	    	if (useHost) {
	    		webhookPostData.add("Host Machine", WebhookData);
	    	}else {
	    		webhookPostData.add("Cloud Instance (Ec2)", WebhookData);
	    	}
	    	
	    	if(!webhookPostData.isJsonNull() && webhookUrl != null && !StringUtils.isEmpty(webhookUrl)) {
	    		Webhook wh = new Webhook(webhookUrl, gson.toJson(webhookPostData), buildLogger, proxyConfiguration);
	    		wh.post();
	    	}
        } catch(Exception e) {
        	String error = " Exception while posting data to webhook. Error: "+ e.getMessage();
        	buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
        	logger.info(error);
        	for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
        } 
    }// end of postWebhookData
}// end of VMScanLauncher class