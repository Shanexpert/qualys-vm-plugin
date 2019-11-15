package com.qualys.plugins.vm.webhook;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.vm.util.Helper;

public class WebhookCriteria {
	private final static Logger logger = Logger.getLogger(Helper.class.getName());
	
	//This method is used to make fail reason for the webhook 
	public static JsonObject makeFailReasonObject(String machine, JsonObject scanReportObj, String byCvss, boolean useHost) {
    	JsonObject returnObj = new JsonObject();    	
    	try {
			JsonObject jsonObj = scanReportObj;
			//severity
			if (!jsonObj.get("severities").isJsonNull()) {
				JsonObject severityObj = jsonObj.get("severities").getAsJsonObject();
				JsonObject severityNewObj = null;
				for (Entry<String, JsonElement> el : severityObj.entrySet()) {
					JsonObject sev = el.getValue().getAsJsonObject();
					if(!sev.get("result").getAsBoolean()) {
						if(severityNewObj == null) severityNewObj = new JsonObject();
						JsonObject obj = new JsonObject();
						obj.add("configured", sev.get("configured"));
						obj.add("found", sev.get("found"));
						severityNewObj.add(el.getKey(), obj);
					}
				}
				if(severityNewObj != null) {
					returnObj.add("severity", severityNewObj);
				}
			}
			
			//qid
			JsonObject qidJ = jsonObj.get("qids").getAsJsonObject();
			String qid_config = qidJ.get("configured").getAsString();
			if (!qid_config.equalsIgnoreCase("0")) {
				JsonObject qidObj = jsonObj.get("qids").getAsJsonObject();
				JsonObject qidNewObj = null;
				if(! qidObj.get("result").getAsBoolean()) {
					if(qidNewObj == null) qidNewObj = new JsonObject();
					qidNewObj.add("configured", qidObj.get("configured"));
					qidNewObj.add("found", qidObj.get("found"));
				}
				if(qidNewObj != null) {
					returnObj.add("qid", qidNewObj);
				}
			}
			
			//cve
			JsonObject cveJ = jsonObj.get("cveIds").getAsJsonObject();
			String cve_config = cveJ.get("configured").getAsString();
			if (!cve_config.equalsIgnoreCase("0")) {
				JsonObject cveObj = jsonObj.get("cveIds").getAsJsonObject();
				JsonObject cveNewObj = null;
				if(! cveObj.get("result").getAsBoolean()) {
					if(cveNewObj == null) cveNewObj = new JsonObject();
					cveNewObj.add("configured", cveObj.get("configured"));
					cveNewObj.add("found", cveObj.get("found"));
				}
				if(cveNewObj != null) {
					returnObj.add("cve", cveNewObj);
				}
			}
			
			//cvss
			if (!jsonObj.get("cvss_base").isJsonNull() 
					|| !jsonObj.get("cvss3_base").isJsonNull()) {				
				makeFailReasonObjectForCvss(byCvss, jsonObj, returnObj);				
			}
			
			//pci
			if (!jsonObj.get("pci_vuln").isJsonNull()) {
				JsonObject pciObj = jsonObj.get("pci_vuln").getAsJsonObject();
				JsonObject pciNewObj = null;
				if(! pciObj.get("result").getAsBoolean()) {
					if(pciNewObj == null) pciNewObj = new JsonObject();
					pciNewObj.add("configured", pciObj.get("configured"));
					pciNewObj.add("found", pciObj.get("found"));
				}
				if(pciNewObj != null) {
					returnObj.add("pci", pciNewObj);
				}
			}
    	}catch(Exception e) {
    		logger.info("Error while making Fail Reason Object: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);    		
    	}
    	return returnObj;
    }// end of makeFailReasonObject
	
	//This method is used to make cvss fail reason
	private static void makeFailReasonObjectForCvss(String cvssVersion, JsonObject jsonObj, JsonObject returnObj) {
		JsonObject cvssObj = jsonObj.get(cvssVersion).getAsJsonObject();
		JsonObject cvssNewObj = null;
		if(! cvssObj.get("result").getAsBoolean()) {
			if(cvssNewObj == null) cvssNewObj = new JsonObject();
			cvssNewObj.add("configured", cvssObj.get("configured"));
			cvssNewObj.add("found", cvssObj.get("found"));
			if (cvssVersion.equalsIgnoreCase("cvss_base")) {
				cvssNewObj.addProperty("version", 2);
			}else {
				cvssNewObj.addProperty("version", 3);
			}
		}
		if(cvssNewObj != null) {
			returnObj.add("cvss", cvssNewObj);
		}
	}// end of makeFailReasonObjectForCvss
	
	//This method is used to make the scan data for the webhook
	public static JsonObject getScanDataForWebhook(JsonObject scanResult, String host, boolean useEc2, String ec2Id) {
		JsonObject webhookData = new JsonObject();    	
    	JsonArray data = new JsonArray();
    	JsonObject scanObj = new JsonObject();
    	JsonObject machineIp = new JsonObject();
    	JsonObject confirmObj, potentialObj;
    	List<String> hostScanList = new ArrayList<String>();
		try{    		
	    	hostScanList.add("hosts_not_scanned_excluded_host_ip");
	    	hostScanList.add("hosts_not_scanned_excluded_host_netbios");
	    	hostScanList.add("hosts_not_scanned_host_not_alive_ip");
	    	hostScanList.add("hosts_not_scanned_host_not_alive_netbios");
	    	hostScanList.add("hosts_not_scanned_hostname_not_found_ip");
	    	hostScanList.add("hosts_not_scanned_hostname_not_found_netbios");
	    	hostScanList.add("hosts_not_scanned_scan_discontinued_ip");
	    	hostScanList.add("hosts_not_scanned_scan_discontinued_netbios");
	    	hostScanList.add("hosts_not_scanned_ip_could_not_be_resolved");
	    	hostScanList.add("hosts_not_scanned_dns_hostname_could_not_be_resolved");
	    	hostScanList.add("hosts_not_scanned_netbios_could_not_be_resolved");
	    	if(scanResult.has("data")) { 
	    		data = scanResult.getAsJsonArray("data");
	    	}
	    	if(data.size() > 2) {
	    		scanObj = data.get(1).getAsJsonObject();
	    		machineIp = data.get(2).getAsJsonObject();
	    	}
	    	confirmObj = new JsonObject();
	    	potentialObj = new JsonObject();
	    	String key = "";
	    	boolean hostNotAlive = false;
	    	Set<String> set = machineIp.keySet();    	
	    	for (String s : hostScanList) {
	    		if (set.contains(s)) {
	       		 key = s;
	    		}
	    	}    	
	    	
	    	if (host.equalsIgnoreCase("No_Host")) hostNotAlive = true;
	    	if (!key.isEmpty()) {
	    		webhookData.addProperty("ip", !machineIp.has("ip") && hostNotAlive ? machineIp.get(key).getAsString() : scanObj.get("ips").getAsString());    	    	
	    	} else {
	    		webhookData.addProperty("ip", machineIp.has("ip") ? machineIp.get("ip").getAsString() : scanObj.get("ips").getAsString());
	    	}
	    	if(hostNotAlive) {
		    	for (String s : set) {
		    		webhookData.addProperty(s, machineIp.get(s).getAsString());
		    	}
	    	}
	    	
	    	if(useEc2) webhookData.addProperty("Ec2Id", ec2Id);
	    	
			// Result Summary
			String[] summaryAttrs = {"launch_date", "total_hosts", "type", "status","reference", 
									"scanner_appliance","duration","scan_title","ips","excluded_ips",
									"option_profile", "network"};
			for(int i = 0; i<summaryAttrs.length; i++) {
				try {				
					webhookData.addProperty(summaryAttrs[i], scanObj.get(summaryAttrs[i]).getAsString());
				}
				catch(NullPointerException exc){
					logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
					webhookData.addProperty(summaryAttrs[i], " - ");
				}
				catch(Exception exc) {
					logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
					webhookData.addProperty(summaryAttrs[i], "Exception: " + exc.getMessage());
				}
			}
			
			if (!hostNotAlive) {
				int confirmedVulns [] = new int[6];
				int potentialVulns [] = new int[6];
				for (JsonElement s: data) {
					JsonObject scanObject = s.getAsJsonObject();
					if(scanObject.has("qid") && scanObject.has("type")) {						
						if (scanObject.get("type").getAsString().equalsIgnoreCase("Vuln")) {							
							if (scanObject.has("severity")) {
							int i = scanObject.get("severity").getAsInt();
							confirmedVulns[i]++;
							}   						
						} else if (scanObject.get("type").getAsString().equalsIgnoreCase("Practice")) {												
							if (scanObject.has("severity")) {
								int i = scanObject.get("severity").getAsInt();   							
								potentialVulns[i]++;
							}
						}
					}   						   			
				}// end of for loop
				for(int i=1 ; i<=5 ; i++) {
					confirmObj.addProperty(Integer.toString(i), confirmedVulns[i]);
					potentialObj.addProperty(Integer.toString(i), potentialVulns[i]);   					
				}
				webhookData.add("Confirmed", confirmObj);
				webhookData.add("Potential", potentialObj);
				webhookData.addProperty("active_hosts", scanObj.get("active_hosts").getAsString());			
			}else {
				webhookData.addProperty("active_hosts", "0");
			}		
    	} catch (Exception e) {
    		logger.info("Excaption while getting scan data for webhook. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);    		
    	}	
	    return webhookData;
    }//end of getScanDataForWebhook
} //End of WebhookCriteria 
