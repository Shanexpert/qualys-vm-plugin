package com.qualys.plugins.vm.criteria;

import com.google.gson.*;
import com.qualys.plugins.vm.util.Helper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class QualysCriteria {
	ArrayList<Integer> qidList;
	HashMap<Integer, Integer> severityMap;
	ArrayList<String> cveList;
	Double cvssBase;
	Double cvssBase3;
	boolean isCvssBase = false;	
	boolean isCvss3Base = false;	
	boolean isSevConfig = false;
	boolean failByPci = false;
	boolean evaluatePotentialVulns = false;
	int pciCount = 0;
	boolean failCheck = true;
	private final static Logger logger = Logger.getLogger(Helper.class.getName());
	
	boolean checkPotentialVulns, sevStaus = true;
	ArrayList<Integer> qidExcludeList =  new ArrayList<Integer>(0);
	ArrayList<String> cveExcludeList  = new ArrayList<String>(0);
	String excludeBy = "";
	ArrayList<String> failedReasons  = new ArrayList<String>(0);
	Gson gsonObject = new Gson();
	private JsonObject returnObject;
	ArrayList<String> configuredQids;	
	ArrayList<String> configuredCves;	
	Set<String> qidsFound = new HashSet<String>(0);	
	Set<String> cveFound = new HashSet<String>(0);
	Set<String> cveEqualys = new HashSet<String>(0);
	ArrayList<Double> cvss_baseFound = new ArrayList<Double>(0);
	ArrayList<Double> cvss3_baseFound = new ArrayList<Double>(0);
	ArrayList<Double> base2GreaterThan = new ArrayList<Double>(0);
	ArrayList<Double> base3GreaterThan = new ArrayList<Double>(0);
	Set<String> exclutableSet = new HashSet<String>();
	Set<Double> exclutableSetD = new HashSet<Double>();
	private int sizeBeforeExclude = 0;
	private int sizeAfterExclude = 0;
	int[] sevFound = new int[6];

	public QualysCriteria(String criteriaJson, boolean failCheck) throws Exception {
		JsonParser jsonParser = new JsonParser();
		JsonElement jsonTree = jsonParser.parse(criteriaJson);
		if (!jsonTree.isJsonObject()) {
			throw new InvalidCriteriaException("Criteria JSON Invalid");
		}
		
		this.failCheck = failCheck;
		this.setDefaultValues();
		JsonObject jsonObject = jsonTree.getAsJsonObject();
		try {
			if (jsonObject.has("failConditions") && this.failCheck == true) {
				JsonObject failConditions = jsonObject.getAsJsonObject("failConditions");				
				// QIDs
				if (failConditions.has("qids") && !failConditions.get("qids").isJsonNull()) {								
					JsonArray qids = null;
					if (failConditions.get("qids") == null || failConditions.get("qids").isJsonNull() || failConditions.get("qids").getAsJsonArray().toString().equalsIgnoreCase("[]")) { 						
						qids = new JsonArray();
						qids.add(0);			
					} else {
						qids = failConditions.get("qids").getAsJsonArray();						
					}
					for (JsonElement qid : qids) {
						String qidString = qid.getAsString();
						configuredQids.add(qidString);
						if (qidString.contains("-")) {
							String[] qidElements = qidString.split("-");
							int start = Integer.parseInt(qidElements[0]);
							int end = Integer.parseInt(qidElements[1]);
							for (int i = start; i <= end; i++) {
								this.qidList.add(i);
							}
						} else {
							this.qidList.add(Integer.parseInt(qidString));
						}
					}
					
				} else {
					logger.info("'qids' not configured in given fail conditions.");
				}
				
				// CVEs
				if (failConditions.has("cve_id") && !failConditions.get("cve_id").isJsonNull()) {
					JsonArray cves = null;
					if (failConditions.get("cve_id") == null || failConditions.get("cve_id").isJsonNull() || failConditions.get("cve_id").getAsJsonArray().toString().equalsIgnoreCase("[]")) { 						
						cves = new JsonArray();
						cves.add(0);			
					} else {
						cves = failConditions.get("cve_id").getAsJsonArray();						
					}		
					for (JsonElement cve : cves) {
						this.cveList.add(cve.getAsString());
						this.configuredCves.add(cve.getAsString());
					}
				} else {
					logger.info("'cves' not configured in given fail conditions.");
				}
				
				// CVSS			
				if (failConditions.has("cvss_base") && !failConditions.get("cvss_base").isJsonNull()) {
					this.cvssBase = (failConditions.get("cvss_base") == null || failConditions.get("cvss_base").toString().equalsIgnoreCase("[]")) ? 0.0 : failConditions.get("cvss_base").getAsDouble();
					this.isCvssBase = true;
				} else {
					logger.info("'cvss_base' not configured in given fail conditions.");
				}			
				if (failConditions.has("cvss3_base") && !failConditions.get("cvss3_base").isJsonNull()) {				
					this.cvssBase3 = (failConditions.get("cvss3_base") == null || failConditions.get("cvss3_base").toString().equalsIgnoreCase("[]")) ? 0.0 : failConditions.get("cvss3_base").getAsDouble();
					this.isCvss3Base = true;
				} else {
					logger.info("'cvss3_base' not configured in given fail conditions.");
				}
	/*
				if (failConditions.has("cvss_temporal") && !failConditions.get("cvss_temporal").isJsonNull()) {
					this.cvssTemporal = failConditions.get("cvss_temporal").getAsDouble();				
				} else {
					logger.info("'cvss_temporal' not found in given JSON.");
				}
				if (failConditions.has("cvss3_temporal") && !failConditions.get("cvss3_temporal").isJsonNull()) {
					this.cvssTemporal3 = failConditions.get("cvss3_temporal").getAsDouble();				
				} else {
					logger.info("'cvss3_temporal' not found in given JSON.");
				}
	*/			
				// Exclude List
				if(failConditions.has("excludeBy")&& !failConditions.get("excludeBy").isJsonNull()) {					
					//Exclude CVEs
					if (failConditions.get("excludeBy").getAsString().equals("cve_id") && failConditions.has("excludeCVEs") && !failConditions.get("excludeCVEs").isJsonNull()) {
						excludeBy = "cve_id";
						JsonArray excludeCVEsList = failConditions.getAsJsonArray("excludeCVEs");
						for (JsonElement excludeCVEElement : excludeCVEsList) {
							String excludeCVEString = excludeCVEElement.getAsString();
							this.cveExcludeList.add(excludeCVEString);												
						}					
					}				
					// Exclude Qids
					if (failConditions.get("excludeBy").getAsString().equals("qid")  && failConditions.has("excludeQids") && !failConditions.get("excludeQids").isJsonNull()) {
						excludeBy = "qid";
						JsonArray excludeQidsList = failConditions.getAsJsonArray("excludeQids");
						for (JsonElement excludeQidElement : excludeQidsList) {
							String excludeQidString = excludeQidElement.getAsString();
							if (excludeQidString.contains("-")) {
								String[] excludeQids = excludeQidString.split("-");	
								int start = Integer.parseInt(excludeQids[0]);
								int end = Integer.parseInt(excludeQids[1]);
								for (int i = start; i <= end; i++) {
									this.qidExcludeList.add(i);								
								}							
							}else {
								this.qidExcludeList.add(Integer.parseInt(excludeQidString));
							}
						}
					}
				}//excludeBy
				
				// Severities
				if (failConditions.has("severities") && !failConditions.get("severities").isJsonNull()) {
					this.isSevConfig = true;
					JsonObject severities = failConditions.getAsJsonObject("severities");
					this.severityMap.put(1,
							!(severities.get("1") == null || severities.get("1").isJsonNull())
									? severities.get("1").getAsInt()
									: -1);
					this.severityMap.put(2,
							!(severities.get("2") == null || severities.get("2").isJsonNull())
									? severities.get("2").getAsInt()
									: -1);
					this.severityMap.put(3,
							!(severities.get("3") == null || severities.get("3").isJsonNull())
									? severities.get("3").getAsInt()
									: -1);
					this.severityMap.put(4,
							!(severities.get("4") == null || severities.get("4").isJsonNull())
									? severities.get("4").getAsInt()
									: -1);
					this.severityMap.put(5,
							!(severities.get("5") == null || severities.get("5").isJsonNull())
									? severities.get("5").getAsInt()
									: -1);
				} else {
					this.severityMap.clear();
					this.severityMap.put(1, -1);
					this.severityMap.put(2, -1);
					this.severityMap.put(3, -1);
					this.severityMap.put(4, -1);
					this.severityMap.put(5, -1);
					logger.info("'severities' not configured in given fail conditions.");
				}
				
				if(failConditions.has("failByPci") && failConditions.get("failByPci").getAsBoolean() == true) {
					this.failByPci = true;
				}else {
					logger.info("'pci_vulns' not configured in given fail conditions.");
				}
				
				if(failConditions.has("evaluatePotentialVulns") && failConditions.get("evaluatePotentialVulns").getAsBoolean() == true) this.evaluatePotentialVulns = true;
				
			} else {
				logger.info("'failConditions' not configured.");
			}
		}catch (Exception e) {
			logger.info("Exception while setting Qualys criteria. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);			
		}
	}// end of Xtor

	private void setDefaultValues() {
		this.qidList = new ArrayList<Integer>();
		this.configuredQids = new ArrayList<String>();
		this.configuredCves = new ArrayList<String>();
		this.severityMap = new HashMap<Integer, Integer>();
		this.cveList = new ArrayList<String>();
		this.cvssBase = new Double(0.0);
		this.cvssBase3 = new Double(0.0);
		this.checkPotentialVulns = false;
		this.returnObject = new JsonObject();
		JsonObject exclude = new JsonObject();
        exclude.add("exclude", null);
		returnObject.add("qids", exclude);
		returnObject.add("severities", null);
		returnObject.add("cveIds", exclude);
		returnObject.add("cvss_base", null);
		returnObject.add("cvss3_base", null);
		returnObject.add("pci_vuln", null);
	} // setDefaultValues
	
	private int setSizeBeforeExclude(JsonObject resultB4Exclude) throws Exception {
		int i = 0;
		try {	
			if(resultB4Exclude.has("data") && !resultB4Exclude.get("data").isJsonNull()) {
				JsonArray getDataInArray = resultB4Exclude.get("data").getAsJsonArray();
				for (JsonElement vuln : getDataInArray) {
					JsonObject scanObject = vuln.getAsJsonObject();
					if (scanObject.has("type") && 
							scanObject.has("qid") && 
							scanObject.get("qid") != null && 
							!scanObject.get("qid").isJsonNull()) 
						i +=1;						
				}			
			}
		} catch (Exception e) {
			logger.info("Exception while checking the size of scan result. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);			
		}
		return i;		
	}

	public Boolean evaluate(JsonObject response) throws Exception {
		Boolean finalStatus = true;
		JsonObject status = new JsonObject();
		if(this.failCheck == true) {
	    	try {
	    		if (this.excludeBy != null && !this.excludeBy.isEmpty()) {    			
	    			this.sizeBeforeExclude = setSizeBeforeExclude(response);    			
	    			JsonObject result = this.excludeVulns(response);			
	    			status = this.evaluateAll(result);
	    			this.sizeAfterExclude = result.get("data").getAsJsonArray().size();    			
	    		}else {    			
	    			status = this.evaluateAll(response);    			
	    		}
	    	}catch (Exception e) {
	    		logger.info("Exception while sending the scan result for evaluation. Error: " + e.getMessage());
	    		for (StackTraceElement traceElement : e.getStackTrace())
	                logger.info("\tat " + traceElement);	    		
	    		}
	
			if(!status.get("sevStatus").getAsBoolean() || 
					!status.get("qidStatus").getAsBoolean()||
					!status.get("cveStatus").getAsBoolean() || 
					!status.get("cvssB2Status").getAsBoolean() || 
					!status.get("cvssB3Status").getAsBoolean()||
					!status.get("pciStatus").getAsBoolean() ) {			
				finalStatus = false;
			}
		}else {
			finalStatus = true;
		}
		
		return finalStatus;
	}// End of evaluate method
	
	@SuppressWarnings("unlikely-arg-type")
	private void dataFound(JsonObject scanObject) {
		
		if (!this.qidList.isEmpty()) {
			Integer qid = 0;
			if (scanObject.has("qid") && scanObject.get("qid") != null && !scanObject.get("qid").isJsonNull()) {								
				qid = scanObject.get("qid").getAsInt();
				if (this.qidList.contains(qid) && !qidsFound.contains(qid.toString())) {
					qidsFound.add(qid.toString());
				}
			}
							
		}//End of Feed the list with found qids
		
		if (this.isSevConfig) {
			if (scanObject.has("severity") && scanObject.get("severity") != null && !scanObject.get("severity").isJsonNull()) {	
				int sevVal = scanObject.get("severity").getAsInt();
				sevFound[sevVal] = sevFound[sevVal] + 1;					
			}				
		}//End of Feed the list with found severities
			
		if(!this.cveList.isEmpty()) {
			if (scanObject.has("cve_id") && scanObject.get("cve_id") != null && !scanObject.get("cve_id").isJsonNull()) {
				String cveVal = scanObject.get("cve_id").getAsString();				
				if (cveVal.contains(",")) {
		    		List<String> newList = Arrays.asList(cveVal.split(","));
		    		newList.replaceAll(String::trim);
		    		cveFound.addAll(newList);
		    	}
		    	else {
		    		cveFound.add(cveVal.trim());
		    	}					
			}				
		}//end of Feed the list with found cves			
		
		if(this.isCvssBase) {
			if (scanObject.has("cvss_base") && scanObject.get("cvss_base") != null && !scanObject.get("cvss_base").isJsonNull()) {				
				String[] cvss =  scanObject.get("cvss_base").getAsString().trim().split(" ");
				double val = Double.parseDouble(cvss[0]);
				cvss_baseFound.add(val);
			}				
		}//End of Feed the list with found cvssV2
	
		if(this.isCvss3Base) {
			if (scanObject.has("cvss3_base") && scanObject.get("cvss3_base") != null && !scanObject.get("cvss3_base").isJsonNull()) {
				String[] cvss =  scanObject.get("cvss3_base").getAsString().trim().split(" ");
				double val = Double.parseDouble(cvss[0]);
				cvss3_baseFound.add(val);						
			}				
		}//End of Feed the list with found cvssV3
		
		if (this.failByPci) {			
			if (scanObject.has("pci_vuln") && scanObject.get("pci_vuln") != null && !scanObject.get("pci_vuln").isJsonNull()) {
				if(scanObject.get("pci_vuln").getAsString().equalsIgnoreCase("yes")) {					
					this.pciCount += 1;					
				}
			}				
		}//End of Feed the list with found PCI
	}// End of dateFound method
	
	
	public JsonObject evaluateAll(JsonObject response) throws Exception {
		HashMap<Integer, Integer> evaluationSev = new HashMap<Integer, Integer>();
		boolean sevStatus = true, qidStatus = true, cveStatus = true, cvssB2Status = true, 
				cvssB3Status = true, pciStatus = true;
//		boolean cvssT2Status = true,cvssT3Status = true;
		JsonObject getStatus =  new JsonObject();
				
		JsonArray getDataInArray = null;
		try {
			getDataInArray = response.get("data").getAsJsonArray();
		} catch (Exception e) {
			logger.info("Exception while getting the scan result for evaluation. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);			
		}
		
		// Iterate over each JSON object in the List
		for (JsonElement vuln : getDataInArray) {
			JsonObject scanObject = vuln.getAsJsonObject();
			
			if (
				scanObject.has("type") && // Check if the JsonObject has type
					(
					 // Check if the JsonObject has type:Vuln or ...
					 scanObject.get("type").getAsString().equalsIgnoreCase("vuln") || 
						(
							// Check if the evaluatePotentialVulns and JsonObject has type:Practice
							evaluatePotentialVulns == true && scanObject.get("type").getAsString().equalsIgnoreCase("practice")
						)
					)
				) {
					dataFound(scanObject);								
				}// End of checking type & Practice or Vuln			
		}// End of for qids, severtities, cves, cvss

		// Evaluate found pci_vuln
		if(!this.failByPci) {
			returnObject.add("pci_vuln", null);			
		}else if(this.failByPci && pciCount == 0) {
			this.setResult(pciCount, pciStatus, "pci_vuln", "yes");
		}else {
			pciStatus = false;
			if (pciStatus == false && !this.qidExcludeList.isEmpty()) {
				failedReasons.add("\n\tFailing this build because found " + pciCount + " PCI vulnerabilities after excluding qids: " + this.qidExcludeList.toString());
			} else if (pciStatus == false && !this.cveExcludeList.isEmpty()) {
				failedReasons.add("\n\tFailing this build because found " + pciCount + " PCI vulnerabilities after excluding cves: " + this.cveExcludeList.toString());
			} else {
				failedReasons.add("\n\tFailing this build because found " + pciCount + " PCI vulnerabilities");
			}
			this.setResult(pciCount, pciStatus, "pci_vuln", "yes");
		}
		getStatus.addProperty("pciStatus", pciStatus);
		
		// Evaluate found cvss_base		
		if(this.isCvssBase) {
			for(Double base2: cvss_baseFound) {
				if (Double.compare(this.cvssBase, base2) <= 0.0) {
					base2GreaterThan.add(base2);
					cvssB2Status = false;
				}
			}
			if (base2GreaterThan.size() > 0) {
				if (cvssB2Status == false && !this.qidExcludeList.isEmpty()) {
					failedReasons.add("\n\tFailing this build because found " +base2GreaterThan.size()+ " CVSSV2 Base score, more than configured:"+ this.cvssBase.toString() + " score. After excluding qids: " + this.qidExcludeList.toString());
				} else if (cvssB2Status == false && !this.cveExcludeList.isEmpty()) {
					failedReasons.add("\n\tFailing this build because found " +base2GreaterThan.size()+ " CVSSV2 Base score, more than configured:"+ this.cvssBase.toString() + " score. After excluding cves: " + this.cveExcludeList.toString());
				} else {
					failedReasons.add("\n\tFailing this build because found " +base2GreaterThan.size()+ " CVSSV2 Base score, more than configured:"+ this.cvssBase.toString() + " score.");
				}
			}
			this.setResult(base2GreaterThan, cvssB2Status, "cvss_base", this.cvssBase);			
		}
		getStatus.addProperty("cvssB2Status", cvssB2Status);
		
		// Evaluate found cvss3_base		
		if(this.isCvss3Base) {			
			for(Double base3: cvss3_baseFound) {
				if (Double.compare(this.cvssBase3, base3) <= 0.0) {
					base3GreaterThan.add(base3);
					cvssB3Status = false;					
				}
			}
			if (base3GreaterThan.size() > 0) {
				if (cvssB3Status == false && !this.qidExcludeList.isEmpty()) {
					failedReasons.add("\n\tFailing this build because found " +base3GreaterThan.size()+ " CVSSV3 Base score, more than configured:"+ this.cvssBase3.toString() + " score. After excluding qids: " + this.qidExcludeList.toString());
				} else if (cvssB3Status == false && !this.cveExcludeList.isEmpty()) {
					failedReasons.add("\n\tFailing this build because found " +base3GreaterThan.size()+ " CVSSV3 Base score, more than configured:"+ this.cvssBase3.toString() + " score. After excluding cves: " + this.cveExcludeList.toString());
				} else {
					failedReasons.add("\n\tFailing this build because found " +base3GreaterThan.size()+ " CVSSV3 Base score, more than configured:"+ this.cvssBase3.toString() + " score.");
				}
			}
			this.setResult(base3GreaterThan, cvssB3Status, "cvss3_base", this.cvssBase3);			
		}
		getStatus.addProperty("cvssB3Status", cvssB3Status);
		
		// Evaluate CVE
		if(!this.cveList.isEmpty()) {			
			for (String cve : this.cveList) {			
				if (cveFound.contains(cve)) cveEqualys.add(cve);			
			} 
			if(this.cveEqualys.size() > 0) cveStatus = false;
			
			if (cveStatus == false && !this.qidExcludeList.isEmpty()) {
				failedReasons.add("\n\tFailing this build because found configured cve(s):"+ this.cveEqualys.toString() + " after excluding qids: " + this.qidExcludeList.toString());
			} else if (cveStatus == false && !this.cveExcludeList.isEmpty()) {
				failedReasons.add("\n\tFailing this build because found configured cve(s):"+ this.cveEqualys.toString() + " after excluding cves: " + this.cveExcludeList.toString());
			} else if(cveStatus == false){
				failedReasons.add("\n\tFailing this build because found configured cve(s):"+ this.cveEqualys.toString());
			}			
		}
		String cveXcludList = Helper.stringListToString(this.cveExcludeList);
		this.setResult(cveEqualys, cveStatus, "cveIds", this.configuredCves, cveXcludList);
		getStatus.addProperty("cveStatus", cveStatus);
			
		// Evaluate severity
		if (this.isSevConfig) {			
			Set<Integer> severityNumbers = new HashSet<Integer>();
			for(int i=1; i <= 5; i++) {				
				int sevCount = sevFound[i];
				evaluationSev.put(i, sevCount);
				if(!this.severityMap.isEmpty() && this.severityMap.get(i) != -1 && sevCount >= this.severityMap.get(i)) {
					sevStatus = false;
					severityNumbers.add(i);				
			    }
			}
			if (sevStatus == false && !this.qidExcludeList.isEmpty()) {
				failedReasons.add("\n\tFailing this build because found Severity"+severityNumbers.toString()+" has more than configured: "+ this.severityMap + " after excluding qids: " + this.qidExcludeList.toString());
			} else if (sevStatus == false && !this.cveExcludeList.isEmpty()) {
				failedReasons.add("\n\tFailing this build because found Severity"+severityNumbers.toString()+" has more than configured: "+ this.severityMap + " after excluding cves: " + this.cveExcludeList.toString());
			} else {
				failedReasons.add("\n\tFailing this build because found Severity"+severityNumbers.toString()+" has more than configured: "+ this.severityMap);
			}			
			this.addSeverities(evaluationSev);			
		}
		getStatus.addProperty("sevStatus", sevStatus);
		
		if (!this.qidList.isEmpty()) {			
			if (qidsFound.size() > 0) {			
				qidStatus = false;
				if (qidStatus == false && !this.qidExcludeList.isEmpty()) {
					failedReasons.add("\n\tFailing this build because found qid(s) - " +qidsFound.toString() + ". Configured:"+ this.configuredQids.toString() + " after excluding qids: " + this.qidExcludeList.toString());
				} else if (qidStatus == false && !this.cveExcludeList.isEmpty()) {
					failedReasons.add("\n\tFailing this build because found qid(s) - " +qidsFound.toString() + ". Configured:"+ this.configuredQids.toString() + " after excluding cves: " + this.cveExcludeList.toString());
				} else {
					failedReasons.add("\n\tFailing this build because found qid(s) - " +qidsFound.toString() + ". Configured:"+ this.configuredQids.toString());
				}				
			} 
		}
		String qidXcludList = Helper.intListToString(this.qidExcludeList);
		this.setResult(qidsFound, qidStatus, "qids", this.configuredQids, qidXcludList);
		getStatus.addProperty("qidStatus", qidStatus);
		
		returnObject.addProperty("potentialVulnsChecked", evaluatePotentialVulns);		
		
		return getStatus;
	} // End of evaluateAll JsonObject 
	
	private void setResult(int dataFound, boolean status, String returnObj, String configVal) {		
		// Configured
		JsonObject dataJson = new JsonObject();
		if(configVal.equalsIgnoreCase("yes")) {
			dataJson.addProperty("configured", String.join(",", configVal)); //configured
		}else {
			dataJson.add("configured", null);
		}		
		//found
		dataJson.addProperty("found", dataFound);
		
		dataJson.addProperty("result", status);		
		returnObject.add(returnObj, dataJson);
	} // end of setResult PCI
	
	private void setResult(ArrayList<Double> dataFound, boolean status, String returnObj, Double configVal) {		
		// Configured
		JsonObject dataJson = new JsonObject();
		if(Double.compare(configVal, 0) >= 0) {
			dataJson.addProperty("configured", String.join(",", configVal.toString())); //configured
		}else {
			dataJson.addProperty("configured", 0);
		}		
		//found
		if(dataFound.isEmpty() || 
				String.join(",", dataFound.toString()).contains("[0]") ||
				String.join(",", dataFound.toString()).contains("[0.0]")) {			
			dataJson.addProperty("found", 0);
		}else {
			dataJson.addProperty("found", dataFound.size());
		}
		dataJson.addProperty("result", status);		
		returnObject.add(returnObj, dataJson);
	} // end of setResult CVSS
	
	private void setResult(Set<String> dataFound, boolean status, String returnObj, ArrayList<String> list, String excluded) {		
		// Configured
		JsonObject dataJson = new JsonObject();
		if(list.size() >0) {
			dataJson.addProperty("configured", String.join(",", list)); //configured
		}else {
			dataJson.addProperty("configured", 0);
		}		
		//found
		if(dataFound.isEmpty() || 
				String.join(",", dataFound.toString()).contains("[0]") ||
				String.join(",", dataFound.toString()).contains("[0.0]")) {
			dataJson.addProperty("found", 0);
		}else {
			dataJson.addProperty("found", String.join(",", dataFound));
		}
		dataJson.addProperty("result", status);
		if(!excluded.isEmpty()) {
			dataJson.addProperty("excluded", excluded.trim());
		}else {
			dataJson.add("excluded", null);
		}		
		returnObject.add(returnObj, dataJson);		
	} // end of setResult for CVE, QID

    private void addSeverities(HashMap<Integer, Integer> counts) {
    	HashMap<Integer, JsonObject> severityResult = new HashMap<Integer, JsonObject>();		
			for (int i = 5; i >= 1; --i) {
				boolean result = true;
				if (this.severityMap.get(i) != -1) {
					if (counts.get(i) >= this.severityMap.get(i)) {
						result = false;
						if (sevStaus)
							sevStaus = false;
					}
				}	
				JsonObject sevJson = new JsonObject();
				//sys
				if(this.severityMap.get(i).intValue() > -1) {
					sevJson.addProperty("configured", this.severityMap.get(i));
				}else {
					sevJson.add("configured", null);
				}
				if(counts.get(i) > 0) {
					sevJson.addProperty("found", counts.get(i));
				}else {
					if(this.severityMap.get(i).intValue() > -1) {
						sevJson.addProperty("found", 0);
					}else {
						sevJson.add("found", null);
					}
				}
				sevJson.addProperty("result", result);
				severityResult.put(i, sevJson);	
			}
			GsonBuilder builder = new GsonBuilder();
			gsonObject = builder.serializeNulls().create(); // for null values
			
			String sevVulnsJson = gsonObject.toJson(severityResult);
			JsonElement sevVulnsElement = gsonObject.fromJson(sevVulnsJson, JsonElement.class);
			returnObject.add("severities", sevVulnsElement);
	} // end of addSeverities

	public String getMyNumbersAsString(ArrayList<Integer> arrayList) {
		if(arrayList.isEmpty()) {
			return "";
		}		
		
		StringBuilder str = new StringBuilder();
		for (int i = 0; i < arrayList.size(); i++) {
			int myNumbersInt = arrayList.get(i);
			str.append(myNumbersInt + ",");
		}
		str.setLength(str.length() - 1);
		return str.toString();
	}// End of getMyNumbersAsString
	
	public JsonObject getResult() {
		return this.returnObject;
	}// end of getResult
	
	public ArrayList<String> getBuildFailedReasons() {
		return (ArrayList<String>) this.failedReasons.stream().distinct().collect(Collectors.toList());
    }// end of getBuildFailedReasons
	
	private JsonObject excludeVulns(JsonObject result) throws Exception {
		JsonArray includedVulns = new JsonArray();
		JsonObject returnVulns = new JsonObject();
		List<String> newList = null;
		JsonArray getDataInArray = null;
		try {
			getDataInArray = result.get("data").getAsJsonArray();
		} catch (Exception e) {
			logger.info("Exception while getting the scan result for exclude criteria. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);			
		}

		for (JsonElement vuln : getDataInArray) {
			JsonObject vulnObject = vuln.getAsJsonObject();
			if (vulnObject.has("type") && 
					(vulnObject.get("type").getAsString().equalsIgnoreCase("Vuln") || 
					 vulnObject.get("type").getAsString().equalsIgnoreCase("Practice"))) {
				if (this.excludeBy.equals("qid") && vulnObject.has("qid")) {
					int qid = vulnObject.get("qid").getAsInt();
					if (!this.qidExcludeList.contains(qid)) {
						includedVulns.add(vuln);
					}
				} else if (this.excludeBy.equals("cve_id") && vulnObject.has("qid")) {					
					int countOfCvesInExcludeList = 0;				
					if (vulnObject.has("cve_id") && !vulnObject.get("cve_id").isJsonNull()) {
						newList = Arrays.asList(vulnObject.get("cve_id").getAsString().split(","));
			    		newList.replaceAll(String::trim);
			    		for (String s: newList) {
			    			if (this.cveExcludeList.contains(s)) {
								countOfCvesInExcludeList++;
							}
			    		}// end of for
			    		if(countOfCvesInExcludeList < newList.size()) {
							includedVulns.add(vuln);
						}// end of counter comparison if
					} else {
						includedVulns.add(vuln);						
			    	}// End of single CVE else
				}// end of else if of cve_id
			}
		}// end of getDataInArray for 
		returnVulns.add("data", includedVulns);
		return returnVulns;
	} // end of excludeVulns

	/**
	 * @return the returnObject
	 */
	public JsonObject getReturnObject() {
		return returnObject;
	}

	/**
	 * @param returnObject the returnObject to set
	 */
	public void setReturnObject(JsonObject returnObject) {
		this.returnObject = returnObject;
	}

	/**
	 * @return the sizeBeforeExclude
	 */
	public int getSizeBeforeExclude() {
		return sizeBeforeExclude;
	}

	/**
	 * @param sizeBeforeExclude the sizeBeforeExclude to set
	 */
	public void setSizeBeforeExclude(int sizeBeforeExclude) {
		this.sizeBeforeExclude = sizeBeforeExclude;
	}

	/**
	 * @return the sizeAfterExclude
	 */
	public int getSizeAfterExclude() {
		return sizeAfterExclude;
	}

	/**
	 * @param sizeAfterExclude the sizeAfterExclude to set
	 */
	public void setSizeAfterExclude(int sizeAfterExclude) {
		this.sizeAfterExclude = sizeAfterExclude;
	}
}// end of QualysCriteria class