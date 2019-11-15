package com.qualys.plugins.vm.client;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.qualys.plugins.vm.auth.QualysAuth;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import hudson.AbortException;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

public class QualysVMClient extends QualysBaseClient {    
	HashMap<String, String> apiMap;
    Logger logger = Logger.getLogger(QualysVMClient.class.getName());
    private static String conRefuse= " Error: Connection refused, contact service provider.";
    private static String exceptionWhileTorun= "Exception to run";
    private static String exceptionWhileToget= "Exception to get";
    private static String responseCode= " Response Code: ";
    private static String nullMessage= " Error: No data. Check credentials or toggle between Host IP/Ec2 Target's radio button. Contact support for more details.";
    private static String empty= ""; 
    public QualysVMClient(QualysAuth auth) {
        super(auth, System.out);
        this.populateApiMap();
    }

    public QualysVMClient(QualysAuth auth, PrintStream stream) {
        super(auth, stream);
        this.populateApiMap();
    }

    private void populateApiMap() {
        this.apiMap = new HashMap<>();
        // Ref - https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf
        this.apiMap.put("aboutDotPhp", "/msp/about.php"); // [GET]
        this.apiMap.put("scannerName", "/api/2.0/fo/appliance/?action=list&output_mode=full"); // [GET]
        this.apiMap.put("ec2ScannerName", "/api/2.0/fo/appliance/?action=list&platform_provider=ec2&include_cloud_info=1&output_mode=full"); // [GET]
        this.apiMap.put("optionProfilesVm", "/api/2.0/fo/subscription/option_profile/vm/?action=list"); // [GET]
        this.apiMap.put("optionProfilesPci", "/api/2.0/fo/subscription/option_profile/pci/?action=list"); // [GET]
        this.apiMap.put("launchVMScan", "/api/2.0/fo/scan/?action=launch"); // [POST]
        this.apiMap.put("cancelVmScan", "/api/2.0/fo/scan/?action=cancel"); // [POST]
        this.apiMap.put("vMScansList", "/api/2.0/fo/scan/?action=list"); /// [GET][POST]
        this.apiMap.put("getScanResult", "/api/2.0/fo/scan/?action=fetch"); // [GET]
        this.apiMap.put("getConnector", "/qps/rest/2.0/search/am/awsassetdataconnector/"); // [GET]
        this.apiMap.put("runConnector", "/qps/rest/2.0/run/am/assetdataconnector"); // [POST]
        this.apiMap.put("getConnectorStatus", "/qps/rest/2.0/get/am/assetdataconnector"); // [GET]
        this.apiMap.put("getInstanceState", "/qps/rest/2.0/search/am/hostasset?fields=sourceInfo.list.Ec2AssetSourceSimple.instanceState,sourceInfo.list.Ec2AssetSourceSimple.region"); // [POST]
    } // End of populateApiMap method
    
    /*API calling methods*/

    public QualysVMResponse aboutDotPhp() throws Exception {
        return this.get(this.apiMap.get("aboutDotPhp"), false);
    } // End of aboutDotPhp
    
    public JsonObject scannerName(boolean useHost) throws Exception {
    	logger.info("Scanner Name is accepted and getting the DOC.");
    	NodeList dataList = null;
    	Document response = null;    	
    	JsonObject scannerList = new JsonObject();
    	QualysVMResponse resp = new QualysVMResponse();
    	String status = "";
    	int retry = 0;
    	try {
	    	while(retry < 3) {
	    		logger.info("Retrying Scanner Name API call: " + retry);
	    		if (useHost) {
	    			resp = this.get(this.apiMap.get("scannerName"), false);
	    		} else {
	    			resp = this.get(this.apiMap.get("ec2ScannerName"), false);
	    		}
				logger.info("Response code received for Scanner Name API call:" + resp.getResponseCode());			
				response = resp.getResponseXml();
				if (resp.getResponseCode() == 401) {
	    			throw new Exception("401 Unauthorised: Access to this resource is denied.");
	    		}else if (resp.getResponseCode() != 200) {
	    			throw new Exception(exceptionWhileToget+" the Scanner list."+responseCode+resp.getResponseCode()+conRefuse);
	    		}
				if(resp != null && resp.getResponseCode() == 200) {					
					if(useHost) {
						scannerList = getScannerDetails(response, false);		
					} else {
						scannerList = getScannerDetails(response, true);
					}
					break;
		    	}else {
		    		retry ++;
		    		dataList = response.getElementsByTagName("RESPONSE");
		    		for (int temp = 0; temp < dataList.getLength(); temp++) {	        			
		    			Node nNode = dataList.item(temp);			
		    			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eElement = (Element) nNode;
		                    throw new Exception("API Error code: " + 
		                    			eElement
		    	                       .getElementsByTagName("CODE")
		    	                       .item(0)
		    	                       .getTextContent() 
		    	                       + " | API Error message: " + 
		    	                       eElement
		    	                       .getElementsByTagName("TEXT")
		    	                       .item(0)
		    	                       .getTextContent());
		    			}		            		
		    		}
		    	}
				
	    	}
    	}catch (Exception e) {
    		if(e.getMessage() == null){
    			throw new Exception(exceptionWhileToget+" the Scanner list."+responseCode+resp.getResponseCode()+nullMessage);
    		} else {
    		throw new Exception(exceptionWhileToget+" the Scanner list."+responseCode+resp.getResponseCode()+" Details: " + e.getMessage());
    		}
	    }
        return scannerList;
    }//End of scannerName
    
    public Set<String> optionProfiles() throws Exception {
    	logger.info("Option Profile is accepted and getting the DOC.");    	   	
    	Set<String> nameList = new HashSet<>(), nameListVM = new HashSet<>(), nameListPCI = new HashSet<>();
    	int retryVM = 0, retryPCI = 0;
    	try {
    		nameListVM = getList(retryVM, "Option Profile VM", "optionProfilesVm");
    		nameListPCI = getList(retryPCI, "Option Profile PCI", "optionProfilesPci");
    	}catch (Exception e) {
    		throw new Exception(e.getMessage());
    	}
    	nameList.addAll(nameListVM);
    	nameList.addAll(nameListPCI);
        return nameList;
    }//End of optionProfiles
    
    public QualysVMResponse launchVmScan(String requestData) throws Exception {
        return this.post(this.apiMap.get("launchVMScan"), requestData,"");
    } // End of launchVmScan
    
    public QualysVMResponse cancelVmScan(String scanRef) throws Exception {
    	return this.post(this.apiMap.get("cancelVmScan") +"&scan_ref="+ scanRef, "", "");
    } // End of cancelVmScan
    
    public QualysVMResponse vMScansList(String statusId) throws Exception {
        return this.get(this.apiMap.get("vMScansList") +"&scan_ref="+ statusId, false);
    } // End of vMScansList
    
    public QualysVMResponse getScanResult(String scanId) throws Exception {
        return this.get(this.apiMap.get("getScanResult") +"&scan_ref="+scanId+"&output_format=json_extended", true);
    } // End of getScanResult
    
    public void testConnection() throws Exception{
    	QualysVMResponse response = new QualysVMResponse();
    	try {
			response = aboutDotPhp();    		
    		if(response.isErrored()) {
    			throw new Exception("Please provide valid API and/or Proxy details." + " Server returned with Response code: " +response.getResponseCode());
    		}else {
    			Document resp = response.getResponseXml();
    			if(response.getResponseCode() < 200 || response.getResponseCode() > 299) {	    				
    				throw new Exception("HTTP Response code from server: " + response.getResponseCode() + ". API Error Message: " + response.getErrorMessage());
    			} else if (response.getResponseCode() != 200){
    				throw new Exception(exceptionWhileTorun+" test connection."+responseCode+response.getResponseCode()+conRefuse);
    			}
    			
    			logger.info("Root element :" + resp.getDocumentElement().getNodeName());
    			String responseCodeString = getTextValueOfXml(resp, "ABOUT", "WEB-VERSION",empty,empty, "connection");		            	
        		logger.info("WEB-VERSION: " + responseCodeString);       			        		
        		
        		if(!responseCodeString.startsWith("8")) {						
					throw new Exception("The QWEB version is less than 8. Version: " + responseCodeString);
    			} // End of if
    		} // end of else
    	}catch(Exception e) {
    		if(e.getMessage() == null){
    			throw new Exception(exceptionWhileTorun+" test connection."+responseCode+response.getResponseCode()+nullMessage);
    		} else {
    			throw new Exception(e.getMessage());
    		}
    	} // End of catchs 
    } // End of testConnection method
    
    public JsonObject getConnector() throws Exception {
    	logger.info("Connector Name is accepted and getting the DOC.");
    	NodeList dataList = null;
    	Document response = null;    	
    	JSONObject connetorList = new JSONObject();
    	JSONObject cList = new JSONObject();
		JsonParser jsonParser = new JsonParser();		
		QualysVMResponse resp = new QualysVMResponse();
		String name  = "";
    	int retry = 0;
    	try {
	    	while(retry < 3) {
	    		logger.info("Retrying Connector Name API call: " + retry);
				resp = this.post(this.apiMap.get("getConnector"),"","");			
				logger.info("Response code received for Connector Name API call:" + resp.getResponseCode());			
				response = resp.getResponseXml();
				if(resp != null && resp.getResponseCode() == 200) {					
					NodeList responseCode = response.getElementsByTagName("responseCode");					
					if(responseCode.item(0).getTextContent().equalsIgnoreCase("SUCCESS")) {
		        		NodeList applinaceList = response.getElementsByTagName("AwsAssetDataConnector");
		        		logger.info("Connector List lenght - " + String.valueOf(applinaceList.getLength()));
		        		for (int temp = 0; temp < applinaceList.getLength(); temp++) {	        			
		        			Node nNode = applinaceList.item(temp);
		        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
			                    Element eElement = (Element) nNode;
			                    //Populate all the connectors
			                    if (!(eElement.getElementsByTagName("name").getLength() > 0)) {
			                    		name = "Unknown";			                    		
		                    	} else {			                    	
			                    name = eElement
					                       .getElementsByTagName("name")
					                       .item(0)
					                       .getTextContent();
		                    	}
		                    	if (!(eElement.getElementsByTagName("id").getLength() > 0)) {
		                    		cList.put("id","Unknown");		                    		
		                    	} else {
		                    	cList.put("id",eElement		                    
				                       .getElementsByTagName("id")
				                       .item(0)
				                       .getTextContent());
		                    	}
		                    	if (!(eElement.getElementsByTagName("connectorState").getLength() > 0)) {
		                    		cList.put("connectorState","Unknown");		                    		
		                    	} else {
		                    	cList.put("connectorState",eElement		                    
				                       .getElementsByTagName("connectorState")
				                       .item(0)
				                       .getTextContent());
		                    	}		                    	
		                    	if (!(eElement.getElementsByTagName("awsAccountId").getLength() > 0)) {
		                    		cList.put("awsAccountId","Unknown");		                    		
		                    	} else {
		                    	cList.put("awsAccountId", eElement
			                    		.getElementsByTagName("awsAccountId")
			                    		.item(0)
			                    		.getTextContent());	
		                    	}
		                    	
			                    connetorList.accumulate(name,cList);
			                    cList = new JSONObject();			                    
		        			}// End of if
		        		}
		        		jsonParser = new JsonParser();
						} else {
							NodeList responseErrorDetails = response.getElementsByTagName("responseErrorDetails");
							if (responseErrorDetails != null) {
								for (int tempE = 0; tempE < responseErrorDetails.getLength(); tempE++) {	        			
				        			Node nNodeE = responseErrorDetails.item(tempE);
				        			if (nNodeE.getNodeType() == Node.ELEMENT_NODE) {
					                    Element eError = (Element) nNodeE;
					                    if ((eError.getElementsByTagName("errorMessage").getLength() > 0) || 
					                    		(eError.getElementsByTagName("errorResolution").getLength() > 0)) {
						                    throw new Exception("Error while getting the Connector names. API Error Message: " 
						                    + eError.getElementsByTagName("errorMessage").item(0).getTextContent() + 
						                    " | API Error Resolution: " 
						                    + eError.getElementsByTagName("errorResolution").item(0).getTextContent());
					                    }
				        			}
				        		}
							}
						}
					break;
					}else {
	        		retry ++;
	        		dataList = response.getElementsByTagName("responseErrorDetails");
	        		for (int temp = 0; temp < dataList.getLength(); temp++) {
	        			Node nNode = dataList.item(temp);	        			
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eError = (Element) nNode;
		                    if ((eError.getElementsByTagName("errorMessage").getLength() > 0) || 
		                    		(eError.getElementsByTagName("errorResolution").getLength() > 0)) {
			                    throw new Exception("Error in getting Connector names. API Error Message: " 
			                    + eError.getElementsByTagName("errorMessage").item(0).getTextContent() + 
			                    " | API Error Resolution: " 
			                    + eError.getElementsByTagName("errorResolution").item(0).getTextContent());
		                    }
		                }		            			
	        		}		            		
	        	}
	    	}
    	}catch (Exception e) {
    		if(e.getMessage() == null){
    			throw new Exception(exceptionWhileToget+" the Connector name list."+responseCode+resp.getResponseCode()+nullMessage);
    		} else {
    			throw new Exception(e.getMessage());
    		}    		
    	}
        return (JsonObject)jsonParser.parse(connetorList.toString());
    }//End of getConnector
    
    public JsonObject runConnector(String connId) throws Exception {
    	logger.info("Running the connector with Id:" + connId);
    	NodeList dataList = null;
    	Document response = null;    	
    	JsonObject connectorState = new JsonObject();
    	QualysVMResponse resp = new QualysVMResponse();
    	int retry = 0;
    	connectorState.addProperty("request", "");    	
    	connectorState.addProperty("connectorState", "");    	
    	
    	try {
	    	while(retry < 3) {
	    		logger.info("Retrying run Connector API call: " + retry);
				resp = this.post(this.apiMap.get("runConnector")+"/"+connId,"","");			
				logger.info("Response code received for run Connector API call:" + resp.getResponseCode());			
				response = resp.getResponseXml();
				connectorState.addProperty("request", resp.getRequest());
				if(resp != null && resp.getResponseCode() == 200) {					
	        		NodeList applinaceList = response.getElementsByTagName("AwsAssetDataConnector");	        		
	        		for (int temp = 0; temp < applinaceList.getLength(); temp++) {	        			
	        			Node nNode = applinaceList.item(temp);
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eElement = (Element) nNode;		                    
	                    	if (!(eElement.getElementsByTagName("connectorState").getLength() > 0)) {
	                    		connectorState.addProperty("connectorState","Unknown");	                    		
	                    	} else {
	                    		connectorState.addProperty("connectorState", eElement
					                       .getElementsByTagName("connectorState")
					                       .item(0)
					                       .getTextContent());
	                    	}		                    
	        			}// End of if
	        		}  
	        		break;
	        	}else {
	        		retry ++;
	        		dataList = response.getElementsByTagName("responseErrorDetails");	        		
	        		for (int temp = 0; temp < dataList.getLength(); temp++) {
	        			Node nNode = dataList.item(temp);	        			
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eError = (Element) nNode;
		                    if ((eError.getElementsByTagName("errorMessage").getLength() > 0) || 
		                    		(eError.getElementsByTagName("errorResolution").getLength() > 0)) {
			                    throw new Exception("Error in running Connector. API Error Message: " 
			                    + eError.getElementsByTagName("errorMessage").item(0).getTextContent() + 
			                    " | API Error Resolution: " 
			                    + eError.getElementsByTagName("errorResolution").item(0).getTextContent());		                
		                    }
		                }		            			
	        		}
	        	}
	    	}
    	}catch (Exception e) {
    		logger.info("Exception while running the connector. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		if(e.getMessage() == null){
    			throw new Exception(exceptionWhileTorun+" the Connector."+responseCode+resp.getResponseCode()+nullMessage);
    		} else {
    			throw new Exception(e.getMessage());
    		}
    	}
        return connectorState;
    }//End of runConnector
    
    public JsonObject getConnectorStatus(String connId2) throws Exception {
    	logger.info("Getting the connector status for Id:" + connId2);
    	NodeList dataList = null;
    	Document response = null;    	
    	JsonObject connectorState = new JsonObject();
    	connectorState.addProperty("request", "");
    	QualysVMResponse resp = new QualysVMResponse();
    	JsonObject state = new JsonObject();
    	int retry = 0;
    	try {
	    	while(retry < 3) {
	    		logger.info("Retrying to get the Connector Status API call: " + retry);
				resp = this.get(this.apiMap.get("getConnectorStatus")+"/"+connId2, false);			
				logger.info("Response code received for run Connector API call:" + resp.getResponseCode());			
				response = resp.getResponseXml();
				connectorState.addProperty("request", resp.getRequest());
				if(resp != null && resp.getResponseCode() == 200) {					
	        		NodeList applinaceList = response.getElementsByTagName("AssetDataConnector");	        		
	        		for (int temp = 0; temp < applinaceList.getLength(); temp++) {	        			
	        			Node nNode = applinaceList.item(temp);
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eElement = (Element) nNode;		                    
	                    	if (!(eElement.getElementsByTagName("connectorState").getLength() > 0)) {
	                    		connectorState.addProperty("connectorState","Unknown");	                    		
	                    	} else {
	                    		connectorState.addProperty("connectorState", eElement
					                       .getElementsByTagName("connectorState")
					                       .item(0)
					                       .getTextContent());
	                    	}		                    		                    		                    	
	        			}// End of if
	        		}
	        		break;
	        	}else {
	        		retry ++;
	        		dataList = response.getElementsByTagName("responseErrorDetails");
	        		for (int temp = 0; temp < dataList.getLength(); temp++) {
	        			Node nNode = dataList.item(temp);	        			
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eError = (Element) nNode;
		                    if ((eError.getElementsByTagName("errorMessage").getLength() > 0) || 
		                    		(eError.getElementsByTagName("errorResolution").getLength() > 0)) {
			                    throw new Exception("Error in getting Connector state. API Error Message: " 
			                    + eError.getElementsByTagName("errorMessage").item(0).getTextContent() + 
			                    " | API Error Resolution: " 
			                    + eError.getElementsByTagName("errorResolution").item(0).getTextContent());
		                    }	
		                }	            			
	        		}	            		
	        	}
	    	}
    	}catch (Exception e) {
    		logger.info("Exception while getting the connector state. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		if(e.getMessage() == null){
    			throw new Exception(exceptionWhileToget+" the Connector state."+responseCode+resp.getResponseCode()+nullMessage);
    		} else {
    			throw new Exception(e.getMessage());
    		}
    	}
    	logger.info("Current Connector State is: "+connectorState);
        return connectorState;
    }//End of getConnectorStatus
    
    public JsonObject getInstanceState(String ec2Id, String accountId) throws Exception {
    	logger.info("Getting the instance state for Id:" + ec2Id);
    	NodeList dataList = null;
    	Document response = null;
    	JsonObject state = new JsonObject();    	
    	state.addProperty("instanceState", "");
    	state.addProperty("endpoint", "");
    	state.addProperty("count", "Unknown");
    	state.addProperty("request", "");
    	state.addProperty("requestBody", "");
    	state.addProperty("requestParam", "");    	

    	QualysVMResponse resp = new QualysVMResponse();
    	int retry = 0;
    	String xmlReqData = "<ServiceRequest> <filters> "
    				+ "<Criteria field=\"instanceId\" operator=\"EQUALS\">" + ec2Id + "</Criteria> "    				
    				+ "<Criteria field=\"accountId\" operator=\"EQUALS\">" + accountId + "</Criteria> "
    			+ "</filters> </ServiceRequest>";
    	try {
	    	while(retry < 3) {
	    		logger.info("Retrying to get the instance state API call: " + retry);
				resp = this.post(this.apiMap.get("getInstanceState"),"",xmlReqData);			
				logger.info("Response code received for instance state API call:" + resp.getResponseCode());			
				response = resp.getResponseXml();
				state.addProperty("request", resp.getRequest());
		    	state.addProperty("requestBody", resp.getRequestBody());
		    	state.addProperty("requestParam", resp.getRequestParam());		    	
		    	
				if(resp != null && resp.getResponseCode() == 200) {					
					NodeList serviceResponse = response.getElementsByTagName("ServiceResponse");
					NodeList applinaceList = response.getElementsByTagName("Ec2AssetSourceSimple");
	        		for (int temp = 0; temp < serviceResponse.getLength(); temp++) {	        			
	        			Node nNode = serviceResponse.item(temp);
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eElement = (Element) nNode;		                    
		                    if(!(eElement.getElementsByTagName("responseCode")
		                    		.item(0).getTextContent().equalsIgnoreCase("SUCCESS"))) {		                    	
		                    	state.addProperty("apiError", eElement.getElementsByTagName("responseCode").item(0).getTextContent());
		                    }else if (eElement.getElementsByTagName("count").getLength() > 0) {
		                    	state.addProperty("count", Integer.parseInt(eElement
					                       .getElementsByTagName("count")
					                       .item(0)
					                       .getTextContent()));	                    		
	                    	} 
	        			}// End of if
	        		} 
	        		
	        		for (int temp = 0; temp < applinaceList.getLength(); temp++) {	        			
	        			Node nNode = applinaceList.item(temp);
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eElement = (Element) nNode;		                    	                    	
	                    	if (!(eElement.getElementsByTagName("instanceState").getLength() > 0)) {
	                    		state.addProperty("instanceState","Unknown");
	                    		
	                    	} else {
	                    	state.addProperty("instanceState", eElement
			                       .getElementsByTagName("instanceState")
			                       .item(0)
			                       .getTextContent());		                    	
	                    	}
	                    	if (!(eElement.getElementsByTagName("region").getLength() > 0)) {
	                    		state.addProperty("endpoint","Unknown");	                    		
	                    	} else {
	                    		state.addProperty("endpoint",eElement
		                    		.getElementsByTagName("region")
		                    		.item(0)
		                    		.getTextContent());
	                    	}		                    
	        			}// End of if
	        		} 
	        		break;
	        	}else {
	        		retry ++;
	        		dataList = response.getElementsByTagName("responseErrorDetails");
	        		for (int temp = 0; temp < dataList.getLength(); temp++) {
	        			Node nNode = dataList.item(temp);	        			
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
		                    Element eError = (Element) nNode;
		                    if ((eError.getElementsByTagName("errorMessage").getLength() > 0) || 
		                    		(eError.getElementsByTagName("errorResolution").getLength() > 0)) {
			                    throw new Exception("Error in getting Instance state. API Error Message: " 
			                    + eError.getElementsByTagName("errorMessage").item(0).getTextContent() + 
			                    " | API Error Resolution: " 
			                    + eError.getElementsByTagName("errorResolution").item(0).getTextContent());
		                    }
		                }		            			
	        		}	            		
	        	}
	    	}
    	}catch (Exception e) {
    		logger.info("Exception while getting the Instance state. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		if(e.getMessage() == null){
    			throw new Exception(exceptionWhileToget+" the Instance state."+responseCode+resp.getResponseCode()+nullMessage);
    		} else {
    			throw new Exception(e.getMessage());
    		}
    	}
    	if (state.has("instanceState") && state.get("instanceState").getAsString().isEmpty()) state.addProperty("instanceState","Unknown");    	  	
    	if (state.has("endpoint") && state.get("endpoint").getAsString().isEmpty()) state.addProperty("endpoint","Unknown");
        return state;
    }//End of getInstanceState
    
   //End of API calling methods 
    
    // Do a [GET] call
    private QualysVMResponse get(String apiPath, Boolean getJson) throws Exception {    	
        QualysVMResponse apiResponse = new QualysVMResponse();
        String apiResponseString = "";
        CloseableHttpClient httpclient = null;
        
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            String making = "Making GET Request: " + url.toString();
            this.stream.println(making);
            apiResponse.setRequest(making);
            httpclient = this.getHttpClient();	
            
            HttpGet getRequest = new HttpGet(url.toString());
        	getRequest.addHeader("Content-Type", "text/xml");
        	getRequest.addHeader("X-Requested-With", "Qualys");
        	getRequest.addHeader("Accept-Charset", "iso-8859-1, unicode-1-1;q=0.8");
        	getRequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
        	
        	CloseableHttpResponse response = httpclient.execute(getRequest); 
        	apiResponse.setResponseCode(response.getStatusLine().getStatusCode());
        	logger.info("Server returned with ResponseCode: "+ apiResponse.getResponseCode());
        	if (apiResponse.getResponseCode() == 401) {
    			throw new Exception("ACCESS DENIED");
    		}else if (apiResponse.getResponseCode() != 200) {
    			throw new Exception(exceptionWhileTorun+" QualysVMResponse GET method."+responseCode+apiResponse.getResponseCode()+conRefuse);
    		}
        	if(response.getEntity()!=null) {        		
	            if (getJson) {
	            	Gson gson = new Gson();
	            	apiResponseString = getresponseString(response);
	            	JsonArray jsonArray = gson.fromJson(apiResponseString, JsonArray.class);	            	
	            	JsonObject finalResult = new JsonObject();
	            	finalResult.add("data", jsonArray);
		            if (!finalResult.isJsonObject()) {
		                throw new InvalidAPIResponseException("apiResponseString is not a Json Object");
		            }		  
		            apiResponse.setResponse(finalResult.getAsJsonObject());
	            }else {	            	
		            apiResponse.setResponseXml(getDoc(response));
	            }// End of inner if-else
        	} // End of If            
        }catch (JsonParseException je) {        	
			apiResponse.setErrored(true);
            apiResponse.setErrorMessage(apiResponseString);            
        } catch (AbortException e) {
			apiResponse.setErrored(true);
	        apiResponse.setErrorMessage(e.getMessage());
			if(e.getMessage() == null){
    			throw new Exception(exceptionWhileTorun+" Qualys VM Response POST method."+responseCode+apiResponse.getResponseCode()+nullMessage);
    		}else {
    			throw new Exception(e.getMessage());
    		}
		} catch (Exception e) {
            apiResponse.setErrored(true);
            apiResponse.setErrorMessage(e.getMessage());
            if(e.getMessage() == null){
    			throw new Exception(exceptionWhileTorun+" Qualys VM Response GET method."+responseCode+apiResponse.getResponseCode()+nullMessage);
    		} else {
    			throw new Exception(e.getMessage());
    		}
        } // End of catch        
        return apiResponse;
    } // End of QualysVMResponse get() method
    
    // Do a [POST] call
    private QualysVMResponse post(String apiPath, String requestData, String requestXmlString) throws Exception {
    	QualysVMResponse apiResponse = new QualysVMResponse();
        String apiResponseString = "";
        CloseableHttpClient httpclient = null;        
        String uri = null; 
        		
        try {
        	URL url = this.getAbsoluteUrl(apiPath);
        	if (!requestData.isEmpty()) {        		
        		uri = url.toString() +"&"+ requestData;
        		apiResponse.setRequestParam(requestXmlString);
        	}else {
        		uri = url.toString();
        	}
        	
            logger.info("Making POST Request: " + uri.toString());
            apiResponse.setRequest(uri.toString());
            httpclient = this.getHttpClient();
            HttpPost postRequest = new HttpPost(uri.toString());
            postRequest.addHeader("accept", "application/xml");
        	postRequest.addHeader("X-Requested-With", "Qualys");        	
        	postRequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
        	
        	if(requestXmlString != null && !requestXmlString.isEmpty()) {  
        		logger.info("POST Request body: "+ requestXmlString);
        		apiResponse.setRequestBody(requestXmlString);
        		postRequest.addHeader("Content-Type", "application/xml");
        		HttpEntity entity = new ByteArrayEntity(requestXmlString.getBytes("UTF-8"));
	        	postRequest.setEntity(entity);
        	}        	
        	CloseableHttpResponse response = httpclient.execute(postRequest); 
        	logger.info("Got the POST response.");
        	apiResponse.setResponseCode(response.getStatusLine().getStatusCode());
        	logger.info("Server returned with ResponseCode:"+ apiResponse.getResponseCode());
        	if (apiResponse.getResponseCode() == 401) {
    			throw new Exception("ACCESS DENIED");
    		}else if (apiResponse.getResponseCode() != 200) {
    			throw new Exception(exceptionWhileTorun+" QualysVMResponse POST method."+responseCode+apiResponse.getResponseCode()+conRefuse);
    		}
        	if(response.getEntity()!=null) {
	            apiResponse.setResponseXml(getDoc(response));
        	} // End of If                
        }catch (JsonParseException je) {        	
			apiResponse.setErrored(true);
            apiResponse.setErrorMessage(apiResponseString);            
		} catch (AbortException e) {
			apiResponse.setErrored(true);
	        apiResponse.setErrorMessage(e.getMessage());
			if(e.getMessage() == null){
    			throw new Exception(exceptionWhileTorun+" Qualys VM Response POST method."+responseCode+apiResponse.getResponseCode()+nullMessage);
    		}else {
    			throw new Exception(e.getMessage());
    		}
		} catch (Exception e) {			
            apiResponse.setErrored(true);
            apiResponse.setErrorMessage(e.getMessage());
            if(e.getMessage() == null){
    			throw new Exception(exceptionWhileTorun+" Qualys VM Response POST method."+responseCode+apiResponse.getResponseCode()+nullMessage);
    		} else {
    			throw new Exception(e.getMessage());
    		}
        }        
        return apiResponse;
    }// End of QualysVMResponse post() method
    
    private Set<String> optionProfilesSet(Document resp, int respCode, String apiTypeName) throws Exception{
    	Set<String> nameList = new HashSet<>();
		NodeList opList = resp.getElementsByTagName("BASIC_INFO");
		logger.info(apiTypeName + " list lenght - " + String.valueOf(opList.getLength()));
		try {
		for (int i = 0; i < opList.getLength(); i++) {	        			
    			Node nNode = opList.item(i);		        			
    			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;
                    nameList.add(eElement
		                       .getElementsByTagName("GROUP_NAME")
		                       .item(0)
		                       .getTextContent()); 
    			}// End of if    					        		
		} // End of outer for loop
		} catch (Exception e) {
			if(e.getMessage() == null){
    			throw new Exception(exceptionWhileToget+" option Profiles Set."+responseCode+respCode+nullMessage);
    		} else {
    			throw new Exception(exceptionWhileToget+" option Profiles Set."+responseCode+respCode+" Error: " + e.getMessage());
    		}			
		}
    	return nameList;
    }//End of optionProfilesSet method
    
    private Set<String> getList(int retry, String apiTypeName, String api) throws Exception{
    	Set<String> opList = new HashSet<>();
    	QualysVMResponse resp = new QualysVMResponse();
    	try{
    		while(retry < 3) {    	
	    		logger.info("Retrying "+apiTypeName+" API call: " + retry);
				resp = this.get(this.apiMap.get(api), false);
				logger.info("Response code received while getting the "+apiTypeName+" API call:" + resp.getResponseCode());
							
				if(resp != null && resp.getResponseCode() == 200) {					
					opList = optionProfilesSet(resp.getResponseXml(), resp.getResponseCode(), apiTypeName);
					break;
				}else if (resp.getResponseCode() == 401) {
	    			throw new Exception("ACCESS DENIED");
	    		}else if (resp.getResponseCode() != 200) {
	     			throw new Exception(exceptionWhileToget+" the "+apiTypeName+" list."+responseCode+resp.getResponseCode()+conRefuse);
	     		}else {
	        		retry ++;
	        		NodeList dataList = resp.getResponseXml().getElementsByTagName("RESPONSE");
	        		for (int temp = 0; temp < dataList.getLength(); temp++) {	        			
	        			Node nNode = dataList.item(temp);			
	        			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
	                        Element eElement = (Element) nNode;
	                        throw new Exception(apiTypeName + " API Error code: " + 
	                        			eElement
	        	                       .getElementsByTagName("CODE")
	        	                       .item(0)
	        	                       .getTextContent() 
	        	                       + " | API Error message: " + 
	        	                       eElement
	        	                       .getElementsByTagName("TEXT")
	        	                       .item(0)
	        	                       .getTextContent());
	        			}
	        		}
	        	} //End of if else
	    	}// End of while
    	}catch (Exception e) {
    		if(e.getMessage() == null){
    			throw new Exception(exceptionWhileToget+" the "+apiTypeName+" list."+responseCode+resp.getResponseCode()+nullMessage);
    		} else {
     			throw new Exception(exceptionWhileToget+" the "+apiTypeName+" list."+responseCode+resp.getResponseCode()+" " + e.getMessage());
     		}
    	}
    	return opList;
    }// end of getList method
    

    private JsonObject getScannerDetails(Document response, boolean ec2) {
    	String accountId = "";
    	String name = "";
    	String status = "";
    	JSONObject scannerObj = new JSONObject();
    	JSONObject scannerList = new JSONObject();
    	try {
	    	NodeList applinaceList = response.getElementsByTagName("APPLIANCE");
			logger.info("Scanner List lenght - " + String.valueOf(applinaceList.getLength()));
			for (int temp = 0; temp < applinaceList.getLength(); temp++) {	        			
				Node nNode = applinaceList.item(temp);
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {
	                Element eElement = (Element) nNode;
	                name = eElement
		                       .getElementsByTagName("NAME")
		                       .item(0)
		                       .getTextContent();
	                status = eElement
		                       .getElementsByTagName("STATUS")
		                       .item(0)
		                       .getTextContent();
	                if (ec2) {
	                	NodeList endpoint0 = eElement
			                       .getElementsByTagName("CLOUD_INFO");		                    
	                    for (int temp0 = 0; temp0 < endpoint0.getLength(); temp0++) {	        			
		        			Node nNode0 = endpoint0.item(temp0);
		        			if (nNode0.getNodeType() == Node.ELEMENT_NODE) {
			                    Element epElement0 = (Element) nNode0;
			                    accountId = epElement0
					                       .getElementsByTagName("ACCOUNT_ID")
					                       .item(0)
					                       .getTextContent();					                  		                    
		        			} //End of endpoint if
		        		} //End of endpoint for loop
	                }// end of ec2 if
	                scannerList.accumulate("status", status);
	                scannerList.accumulate("accountId", accountId);                
	                scannerObj.accumulate(name, scannerList);                
	                scannerList = new JSONObject();
				}// End of if
			} // end of for
    	}catch(Exception e) {
    		throw e;
    	}
		JsonParser jsonParser = new JsonParser();
		return (JsonObject)jsonParser.parse(scannerObj.toString());
    }// end of getScannerDetails method

    public String getTextValueOfXml(Document doc, String topNode, String topPath, String innerNode,String innerPath, String message) throws Exception{
    	String topResponseString = "Unknown";
    	String innerResponseString = "Unknown";
    	try {
	    	NodeList topList = doc.getElementsByTagName(topNode);
			for (int i = 0; i < topList.getLength(); i++) {	        			
				Node tNode = topList.item(i);			
				if (tNode.getNodeType() == Node.ELEMENT_NODE) {
	                Element topElement = (Element) tNode;	                
                	if (topElement.getElementsByTagName(topPath).getLength() > 0) {
                		topResponseString = topElement
                               .getElementsByTagName(topPath)
                               .item(0)
                               .getTextContent();
                	}
                	if(!innerNode.isEmpty()) {
                		NodeList innerList = topElement.getElementsByTagName(innerNode);
                		for (int j = 0; j < innerList.getLength(); j++) {	        			
                			Node iNode = innerList.item(j);			
                			if (iNode.getNodeType() == Node.ELEMENT_NODE) {
                                Element element = (Element) iNode;
                                if (element.getElementsByTagName(innerPath).getLength() > 0) {
                                	innerResponseString = topElement
                                           .getElementsByTagName(innerPath)
                                           .item(0)
                                           .getTextContent();
                            	}
                			}
                		}
                	}         
				}
			}
    	}catch (Exception e) {
    		logger.info("Exception while getting the text value of XML. Error: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		throw e;
    	}
		if(!innerNode.isEmpty()){
			return innerResponseString;
		}else {
			return topResponseString;
		}
    }// End of getTextValueOfXml String
    
    private Document getDoc(CloseableHttpResponse response) throws Exception {
    	String apiResponseString = "";
    	Document doc = null;
    	try {
    		apiResponseString = getresponseString(response);
    		 if (!apiResponseString.contains("<?xml")) {
             	throw new InvalidAPIResponseException("apiResponseString is not proper XML.");
             }
            // Parse the XML response to XML Document
//	            logger.info(apiResponseString);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            try {
            	factory.setValidating(false); 
            	factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    		} catch (ParserConfigurationException ex) {    			
    			logger.info("Exception for XML external entity while getting Document. Reason: " + ex.getMessage()+ "\n");    	    	
    	    	return doc;
    		}            
            DocumentBuilder builder = factory.newDocumentBuilder();
            ByteArrayInputStream input = new ByteArrayInputStream(apiResponseString.toString().getBytes("UTF-8"));
            doc = builder.parse(input);
            doc.getDocumentElement().normalize();
            logger.info("Root element :" + doc.getDocumentElement().getNodeName());	            
    	}catch (Exception e) {
    		String error = "Exception while getting Document. Reason: " + e.getMessage()+ "\n";
    		logger.info(error);
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		throw new Exception(error);
    	}
    	return doc;    	
    }// end of getDoc method
    
    private String getresponseString(CloseableHttpResponse response) throws Exception {
    	String apiResponseString = "";
    	try {
    		BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), "iso-8859-1"));
            String output;
            while ((output = br.readLine()) != null) {
                apiResponseString += output;
            }
    	}catch (Exception e) {
    		String error = "Exception while getting response String. Error: " + e.getMessage();
    		logger.info(error);
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    		throw new Exception(error);
    	}
		return apiResponseString;
    } 
} // end of QualysVMClient Class