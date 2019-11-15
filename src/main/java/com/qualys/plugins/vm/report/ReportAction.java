package com.qualys.plugins.vm.report;

import java.io.File;
import java.io.StringReader;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.bind.JavaScriptMethod;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import com.qualys.plugins.vm.auth.QualysAuth;
import com.qualys.plugins.vm.client.QualysVMClient;
import com.qualys.plugins.vm.client.QualysVMResponse;
import com.qualys.plugins.vm.util.Helper;
import hudson.AbortException;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.Run;
import net.sf.json.JSONObject;

@Extension
public class ReportAction implements Action {
    private String scanId;
    private String scanRef;
    private String status;
    private String subScanStatus;
    private String scanReference;
    private String scanName;
    private String portalUrl; 
    private String duration;
    private String reference; 
    private String scanType;
    private String scanTarget;
    private String reportUrl;
    private String apiServer;
    private String apiUser;
    private String apiPass;
    private boolean useProxy;
    private String proxyServer;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;    
    private JSONObject scanResult;
    
    private Run<?, ?> run;
	private String scannerName;
    
    private final static Logger logger = Helper.getLogger(ReportAction.class.getName());

    public ReportAction() { }

    public ReportAction(Run<?, ?> run, String scanRef, String scanId, String scanTarget, String scannerName,
    		String scanName, String apiServer, String apiUser, String apiPass, boolean useProxy, 
    		String proxyServer, int proxyPort, String proxyUsername, String proxyPassword, 
    		String duration, String reference, String scanType, String scanStatus, String subScanStatus) {
        this.scanId = scanId;
        this.scanRef = scanRef;
        this.scanName = scanName;
        this.scannerName = scannerName;
        this.apiServer = apiServer;
        this.apiUser = apiUser;
        this.apiPass = apiPass;
        this.useProxy = useProxy;
        this.proxyServer = proxyServer;
        this.proxyPort = proxyPort;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.portalUrl = apiServer;
        this.status = scanStatus;
        this.subScanStatus = subScanStatus;
        this.duration = duration;
        this.scanTarget = scanTarget;
        this.reference = reference;
        this.scanType = scanType;
        this.reportUrl = (portalUrl.endsWith("/")? portalUrl : portalUrl + "/") + "fo/report/report_view.php?&id=" + scanId;        
        this.run = run;
    }
    
    public String getScanId() {
    	return this.scanId;
    }
        
    public String getScanTarget() {
    	return this.scanTarget.toString();
    }
    
    public String getScanName() {
    	return this.scanName;
    }
    
    public String getReportUrl() {
    	return this.reportUrl;
    }
    
    public String getBuildStatus() {
//    	return this.run.getBuildStatusSummary().message;
    	String buildStatus = this.run.getBuildStatusUrl();
    	if(buildStatus.contains("red")) {
    		return "FAILED";
    	}else {
    		return "PASSED";
    	}				
    }
    
    @JavaScriptMethod
    public JSONObject getScanResults() {
    	this.scanResult = new JSONObject();
    	JsonObject respObj = null;
    	QualysVMResponse response = null;
    	JSONObject confirmObj = new JSONObject();
		JSONObject potentialObj = new JSONObject();
		int qids = 0, igs = 0, cVuln = 0, pVuln = 0;
    	try {    		
    		String scanIdNew = scanRef.replace("/","_");    		
    		String filename = run.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_" + scanIdNew + ".json";    		
        	File f = new File(filename);
        	Gson gson = new Gson();
        	if(f.exists()){
        		String resultStr = FileUtils.readFileToString(f);
        		String resultStrClean = resultStr;
        		JsonReader jr = new JsonReader(new StringReader(resultStrClean.trim())); 
        		jr.setLenient(true); 
        		respObj = gson.fromJson(jr, JsonObject.class);        		
        	}else if (this.status.equalsIgnoreCase("Finished")){
        		try {
        			QualysAuth auth = new QualysAuth();
        	    	auth.setQualysCredentials(this.apiServer, this.apiUser, this.apiPass);
        	    	if(useProxy) {
        	        	//int proxyPortInt = Integer.parseInt(proxyPort);
        	        	auth.setProxyCredentials(this.proxyServer, this.proxyPort, this.proxyUsername, this.proxyPassword, this.useProxy);
        	    	}
        	    	QualysVMClient qualysClient = new QualysVMClient(auth, System.out);
	            	response = qualysClient.getScanResult(scanRef);
        		}catch(Exception e) {
        			for (StackTraceElement traceElement : e.getStackTrace())
                        logger.info("\tat " + traceElement);
        			throw new Exception(e);
        		}   
        		respObj = response.getResponse();
        	}
        	//if failOnconditions configured then only we will have evalResult
        	if(respObj != null && (respObj.has("evaluationResult") && !respObj.get("evaluationResult").isJsonNull())){
        		scanResult.put("isEvaluationResult", 1);
        		JsonElement respEl = respObj.get("evaluationResult");
       			JsonObject evalresult = respEl.getAsJsonObject();
       			
       			GsonBuilder builder = new GsonBuilder();
    			Gson gsonObject = builder.serializeNulls().create(); // for null values
    			
    			String sevVulnsJson = gsonObject.toJson(evalresult);
    			JsonElement sevVulnsElement = gsonObject.fromJson(sevVulnsJson, JsonElement.class);
    			
       			scanResult.put("evaluationResult", JSONObject.fromObject(gsonObject.toJson(sevVulnsElement)));
        	}else {
        		scanResult.put("isEvaluationResult", 0);
        		scanResult.put("evaluationResult", JSONObject.fromObject("{}"));
        	}
        	
   			if(respObj == null || !respObj.has("data")) {
   				for(int i=1 ; i<=5 ; i++) {
   					confirmObj.put(Integer.toString(i), cVuln);
   					potentialObj.put(Integer.toString(i), pVuln);   					
   				}
   				scanResult.put("qidsCount", 0);
   				scanResult.put("igsCount", 0);
   				scanResult.put("cVulnCount", cVuln);   				
   				scanResult.put("pVulnCount", pVuln);   				
   				scanResult.put("cVulnsBySev", confirmObj);
   				scanResult.put("pVulnsBySev", potentialObj);
   			//Vuln table   				
				scanResult.put("vulnsTable", JSONObject.fromObject(gson.toJson(Helper.removeBigData(respObj))));				
   			}else {
   				JsonArray dataArr = respObj.get("data").getAsJsonArray();
   				JsonObject scanObj = dataArr.get(1).getAsJsonObject();
   				
   				// Result Summary 
   				
   				String[] summaryAttrs = {"launch_date", "type", "status", "duration", "network"};
   				for(int i = 0; i<summaryAttrs.length; i++) {
					try {
						scanResult.put(summaryAttrs[i], scanObj.get(summaryAttrs[i]).getAsString());
					}
					catch(NullPointerException exc){
						logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
						scanResult.put(summaryAttrs[i], " - ");
					}
					catch(Exception exc) {
						logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
						scanResult.put(summaryAttrs[i], "Exception: " + exc.getMessage());
					}
				}
   				// Result stats 
   				int confirmedVulns [] = new int[6];
				int potentialVulns [] = new int[6];
   				for (JsonElement s: dataArr) {
   					JsonObject scanObject = s.getAsJsonObject();
   					if(scanObject.has("qid") && scanObject.has("type")) {
   						qids++;
   						if (scanObject.get("type").getAsString().equalsIgnoreCase("Ig") ) {	   						
	   						igs++;
   						}	
   						if (scanObject.get("type").getAsString().equalsIgnoreCase("Vuln")) {
   							cVuln++;
   							if (scanObject.has("severity")) {
	   							int i = scanObject.get("severity").getAsInt();
	   							confirmedVulns[i]++;
   							}   						
   						} else if (scanObject.get("type").getAsString().equalsIgnoreCase("Practice")) {
   							pVuln++;   							
   							if (scanObject.has("severity")) {
   								int i = scanObject.get("severity").getAsInt();   							
   								potentialVulns[i]++;
   							}
   						}
   					}   						   			
   				}// end of for loop
   				for(int i=1 ; i<=5 ; i++) {
   					confirmObj.put(Integer.toString(i), confirmedVulns[i]);
   					potentialObj.put(Integer.toString(i), potentialVulns[i]);   					
   				}
   				scanResult.put("qidsCount", qids);
   				scanResult.put("igsCount", igs);
   				scanResult.put("cVulnCount", cVuln);   				
   				scanResult.put("pVulnCount", pVuln);   				
   				scanResult.put("cVulnsBySev", confirmObj);
   				scanResult.put("pVulnsBySev", potentialObj);   				
   				
   			//Vuln table   				
				scanResult.put("vulnsTable", JSONObject.fromObject(gson.toJson(Helper.removeBigData(respObj))));
   			}// end of else
    	}catch(Exception e) {    		
    		logger.info("Error parsing scan Result: " + e.getMessage());
    		scanResult.put("error", e.getMessage());    		
    	}    	
    	return scanResult;
    }
    
    @JavaScriptMethod
    public JSONObject getStatus() {
    	JSONObject statusDetails = new JSONObject();
    	try {
    		if(status!=null && status.equalsIgnoreCase("Finished")) {
    			statusDetails.put("value", status);
    			statusDetails.put("subStatus", subScanStatus);
        		statusDetails.put("cssClass", "success");        		
        		statusDetails.put("reference", this.reference);
    		}else {
    			statusDetails = parseScanStatus(scanRef);
	    		if(statusDetails.get("value").equals("Finished")) {
	    			this.status = "Finished";
	    		}	    		
    		}
    	}catch(Exception e) {
    		logger.warning("Exception in get result Status. Error: " + e.getMessage());
    		statusDetails.put("value", e.getMessage());
    		statusDetails.put("cssClass", "error");
    	}
    	
    	return statusDetails;
    }
    
    public JSONObject parseScanStatus(String scanIdRef) throws Exception {
    	JSONObject statusObj = new JSONObject();
    	Document result = null;
    	try {
    		QualysAuth auth = new QualysAuth();
	    	auth.setQualysCredentials(this.apiServer, this.apiUser, this.apiPass);
	    	if(useProxy) {
	        	//int proxyPortInt = Integer.parseInt(proxyPort);
	        	auth.setProxyCredentials(this.proxyServer, this.proxyPort, this.proxyUsername, this.proxyPassword, this.useProxy);
	    	}
	    	QualysVMClient qualysClient = new QualysVMClient(auth, System.out);
    		QualysVMResponse resp = qualysClient.vMScansList(scanIdRef);
    		result = resp.getResponseXml();
    		//parse result
   			Integer respCodeObj = resp.getResponseCode();
   			if(respCodeObj == null || respCodeObj != 200 ) {
   				String error = resp.getErrorMessage().toString();   				
   				logger.info("Error while fetching the scan result from report. Server returned: " + error +". Please do retry after sometime.");
   				throw new AbortException("Error while fetching the scan result from report. Server returned: " + error +". Please do retry after sometime.");   				
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
	                    	this.status = eElement.getElementsByTagName("STATE").item(0).getTextContent().trim();	
	                    }
	                    if (eElement.getElementsByTagName("STATE").item(0).getTextContent().trim().equalsIgnoreCase("Finished")) {
	                    	if (eElement.getElementsByTagName("SUB_STATE").getLength() > 0 ) {
		                    	this.subScanStatus = eElement.getElementsByTagName("SUB_STATE").item(0).getTextContent().trim();	
		                    }else {
		                    	this.subScanStatus = "Scan Successful";
		                    }
	                    }
	            		} // End of if	                    
        			} // End of Outer if   				
        		logger.info("Scan Status: " + this.status);
        		logger.info("Scan subScanStatus: " + this.subScanStatus);
				try {   						   					
   					statusObj.put("reference", this.reference);	   					
				}catch(Exception e) {
					//these values if not received in status api call will overwritten in getScanResult api call
					if(statusObj.get("reference") != null) statusObj.put("reference", "");   						
				}
				
				if(this.status.equalsIgnoreCase("Finished")) {
					statusObj.put("value", "Finished");
					statusObj.put("subStatus", subScanStatus);
					statusObj.put("cssClass", "success");
				}else {
					statusObj.put("value", this.status);
					statusObj.put("subStatus", subScanStatus);
					statusObj.put("cssClass", "info");
					statusObj.put("resultsStatus", this.status);
	   					
	   			}
   			}
    	} catch(Exception e) {
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		throw e;
    	}    		
    	return statusObj;
    }

	@Override
	public String getIconFileName() {
		return "clipboard.png";
	}

	@Override
	public String getDisplayName() {
		return "Qualys Report for " + this.scanTarget.toString();
	}

	@Override
	public String getUrlName() {		
		return "qualys_vm_scan_report_"+this.scanTarget.toString()+".html";
	}
}