package com.qualys.plugins.vm;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.verb.POST;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.gson.JsonObject;
import com.qualys.plugins.vm.client.QualysVMClient;
import com.qualys.plugins.vm.util.Helper;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import jenkins.model.Jenkins;

public class DescriptorImplQualys {
	private static final String URL_REGEX = "^(https?)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    private static final String WEBHOOK_URL_REGEX = "(https?:\\/\\/(?:www\\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\\.[^\\s]{2,}|www\\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\\.[^\\s]{2,}|https?:\\/\\/(?:www\\.|(?!www))[a-zA-Z0-9]+\\.[^\\s]{2,}|www\\.[a-zA-Z0-9]+\\.[^\\s]{2,})";
    private static final String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&@#/%?=~_|!,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    private static final String TIMEOUT_PERIOD_REGEX = "^(\\d+[*]?)*(?<!\\*)$";
    private static final String HOST_IP = "^\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b";
    private static final String awsAccountId = "awsAccountId";
    private static final String utf8Error = "Provide valid UTF-8 string value.";
    private static final String functionName = "qualysVulnerabilityAnalyzer";
    private static final String displayName = "Evaluate host/instances with Vulnerability Management";
    static JsonObject ctorNameList = new JsonObject();
    private final static Logger logger = Logger.getLogger(Helper.class.getName());
    Helper h = new Helper();
    
	public String getFunctionName() { return functionName; }
    
    public String getDisplayName() { return displayName; }
    
    public boolean isNonUTF8String(String string) {
    	if(string != null && !string.isEmpty()) {
        	try 
        	{
        	    byte[] bytes = string.getBytes(java.nio.charset.StandardCharsets.UTF_8);        	    
        	} 
        	catch (Exception e){        			    		
	    	    return true;
        	}
    	}
    	return false;
    } // End of isNonUTF8String method
    
    @POST
    public ListBoxModel doFillBySevItems() {
    	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
    	ListBoxModel model = new ListBoxModel();
    	for(int i=5; i>=1; i--) {
    		Option e1 = new Option(Integer.toString(i), Integer.toString(i));
	    	model.add(e1);
    	}
    	return model;
    }
    
    public FormValidation doCheckApiServer(String apiServer) {
    	if(isNonUTF8String(apiServer)) {
        	return FormValidation.error(utf8Error);
        }
    	try {
    		String server = apiServer != null ? apiServer.trim() : "";
        	Pattern patt = Pattern.compile(URL_REGEX);
            Matcher matcher = patt.matcher(server);
        	
            if (!(matcher.matches())) {
                return FormValidation.error("Server name is not valid!");
            } else {
            	 return FormValidation.ok();
            }
        } catch (Exception e) {
            return FormValidation.error(e.getMessage());
        }
    } // End of doCheckApiServer FormValidation
    
    public FormValidation doCheckCredsId(String credsId) {
        try {
            if (credsId.trim().equals("")) {
                return FormValidation.error("API Credentials cannot be empty.");
            } else {
                return FormValidation.ok();
            }
        } catch (Exception e) {
            return FormValidation.error(e.getMessage());
        }
    }// End of doCheckCredsId FormValidation
    
    @POST
    public ListBoxModel doFillCredsIdItems(Item item, String credsId) {
    	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        StandardListBoxModel result = new StandardListBoxModel();
        if (item == null) {
        	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
            	return result.add(credsId);
            }
        } else {
        	if (!item.hasPermission(Item.EXTENDED_READ)
                    && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
            	return result.add(credsId);
            }
        }
        return result
                .withEmptySelection()
                .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                .withMatching(CredentialsMatchers.withId(credsId));
    } // End of doFillCredsIdItems FormValidation
    
    public FormValidation doCheckProxyServer(String proxyServer) {
    	if(isNonUTF8String(proxyServer)) {
        	return FormValidation.error(utf8Error);
        }
    	try {
        	Pattern patt = Pattern.compile(PROXY_REGEX);
            Matcher matcher = patt.matcher(proxyServer);
        	
            if (!(matcher.matches())) {
                return FormValidation.error("Enter valid server url!");
            } else {
                return FormValidation.ok();
            }
        } catch (Exception e) {
            return FormValidation.error(e.getMessage());
        }
    } // End of doCheckProxyServer FormValidation
    
    @POST
    public ListBoxModel doFillProxyCredentialsIdItems(Item item, String proxyCredentialsId) {
    	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
    	StandardListBoxModel result = new StandardListBoxModel();
        if (item == null) {
        	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
            	return result.add(proxyCredentialsId);
            }
        } else {
        	if (!item.hasPermission(Item.EXTENDED_READ)
                    && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
            	return result.add(proxyCredentialsId);
            }
        }
        return result
                .withEmptySelection()
                .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                .withMatching(CredentialsMatchers.withId(proxyCredentialsId));
    } // end of doFillProxyCredentialsIdItems

    public FormValidation doCheckProxyPort(String proxyPort) {
    	try {
    		if (proxyPort != null && !proxyPort.trim().isEmpty()) {
    			int proxyPortInt = Integer.parseInt(proxyPort);
    			if(proxyPortInt < 1 || proxyPortInt > 65535) {
    				return FormValidation.error("Enter a valid port number!");
    			}
    		}else {
    			return FormValidation.error("Enter a valid port number!");
    		}
    	} catch(Exception e) {
    		return FormValidation.error("Enter valid port number!");
    	}
    	return FormValidation.ok();
    } // End of doCheckProxyPort FormValidation

    @POST
    public FormValidation doCheckConnection(String apiServer, String credsId,
    		String proxyServer, String proxyPort, String proxyCredentialsId, 
    		boolean useProxy, Item item) {
    	try {
        	int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
    		String server = apiServer != null ? apiServer.trim() : "";  
    		QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);
        	client.testConnection();
        	return FormValidation.okWithMarkup("Connection test successful!");
            
        } catch (Exception e) {        	
        	return FormValidation.error("Connection test failed. (Reason: " + e.getMessage() + ")");
        }
    } // End of doCheckConnection FormValidation
    
    public FormValidation doCheckHostIp(String hostIp) {
    	try {
    		if (hostIp != null && StringUtils.isNotBlank(hostIp)) {        			
    			Pattern patt = Pattern.compile(HOST_IP);
                Matcher matcher = patt.matcher(hostIp);                	
                if (!(matcher.matches())) {
                    return FormValidation.error("Host IP is not valid!");
                } else {
                	 return FormValidation.ok();
                }
    		}else {        			
    			return FormValidation.error("Provide a valid Host IP.");
    		}
    	} catch(Exception e) {
    		return FormValidation.error("Enter valid Host Ip!");
    	}        	
    } // End of doCheckHostIp FormValidation

    public FormValidation doCheckScanName(String scanName) {
    	if(isNonUTF8String(scanName)) {
        	return FormValidation.error(utf8Error);
        }
    	try {
            if (scanName.trim().equals("")) {
                return FormValidation.error("Scan Name cannot be empty.");
            } else {
            	if(scanName.length() > 256) {
            		return FormValidation.error("Scan Name length must be of 256 or less characters.");
            	}
                return FormValidation.ok();
            }
        } catch (Exception e) {
            return FormValidation.error(e.getMessage());
        }
    } // End of doCheckScanName FormValidation     
    
    public FormValidation doCheckEc2Id(String ec2Id) {
    	if(isNonUTF8String(ec2Id)) {
    		return FormValidation.error("Provide valid EC2 Instance Id.");
    	}
    	try {
    		if (ec2Id.trim().equals("")) {
    			return FormValidation.error("EC2 Instance Id cannot be empty.");
    		} else {
    			return FormValidation.ok();
    		}
    	} catch (Exception e) {
    		return FormValidation.error(e.getMessage());
    	}      	
    } // End of doCheckEc2Id FormValidation
    
    public FormValidation doCheckScannerName(String scannerName) {        	
    	try {
    		if (scannerName.trim().equals("")) {
    			return FormValidation.error("Select a Scanner Name.");
    		} else {
    			return FormValidation.ok();
    		}
    	} catch (Exception e) {
    		return FormValidation.error(e.getMessage());
    	}
    } // End of doCheckScannerName FormValidation
    
    public FormValidation doCheckQidList(String qidList) {
    	if (qidList == null || qidList.isEmpty()) {
    		return FormValidation.ok();
    	}
    	try {
    		if(!Helper.isValidQidList(qidList)) {
        		return FormValidation.error("Enter valid QID range/numbers!");
        	}
        	return FormValidation.ok();
    	} catch(Exception e) {
    		return FormValidation.error("Enter valid QID range/numbers! Error:" + e.getMessage());
    	}        	
    } // End of doCheckQidList FormValidation
    
    public FormValidation doCheckCveList(String cveList) {
    	if(!Helper.isValidCVEList(cveList)) {
    		return FormValidation.error("Enter valid CVEs! Given: " + cveList);
    	}
    	return FormValidation.ok();
    } // End of doCheckCveList FormValidation
    
    public FormValidation doCheckCvssBase(String cvssBase) {
    	try {
    		if (cvssBase != null && !cvssBase.isEmpty()) {        			
    			double cvssDouble = 0.0;
    			try {
    				cvssDouble = Double.parseDouble(cvssBase);
					if(cvssDouble < 0.0 || cvssDouble > 10.0) {
						return FormValidation.error("Enter a number in range of 0.0 to 10.0");
					}
				} catch (NumberFormatException e) {
					return FormValidation.error("Input is not a valid number. " + e.getMessage());        				    
				}        			
    		}
    	} catch(Exception e) {
    		return FormValidation.error("Enter valid number!");
    	}
    	return FormValidation.ok();        	
    } // End of doCheckCvssBase FormValidation
  
    public FormValidation doCheckPollingInterval(String pollingInterval) {
        try {
        	String pollingIntervalVal = pollingInterval.trim(); 
        	if (pollingIntervalVal.equals("")) {
         	    return FormValidation.ok();
        	 }
        	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
             Matcher matcher = patt.matcher(pollingIntervalVal);
         	
             if (!(matcher.matches())) {
                 return FormValidation.error("Timeout period is not valid!");
             }
        } catch (Exception e) {
        	return FormValidation.error("Timeout period string : " + pollingInterval + ", reason = " + e);
        }
        return FormValidation.ok();
    } // End of doCheckPollingInterval FormValidation

    public FormValidation doCheckVulnsTimeout(String vulnsTimeout) {
        String vulnsTimeoutVal = vulnsTimeout.trim();
    	try {
        	 if (vulnsTimeoutVal.equals("")) {
         	    return FormValidation.ok();
        	 }
        	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
             Matcher matcher = patt.matcher(vulnsTimeoutVal);
         	
             if (!(matcher.matches())) {
                 return FormValidation.error("Timeout period is not valid!");
             } else {
                 return FormValidation.ok();
             }
        } catch (Exception e) {
        	return FormValidation.error("Timeout period string : " + vulnsTimeout + ", reason = " + e);
        }
    } // End of doCheckVulnsTimeout FormValidation
    
    public FormValidation doCheckExcludeList(String excludeList, String excludeBy) {
    	try {        		
    		if (excludeList != null && !excludeList.isEmpty() && 
    				excludeBy.equalsIgnoreCase("cve_id") && !Helper.isValidCVEList(excludeList)) {    			
				return FormValidation.error("Enter valid CVEs! Given:" + excludeList);		           			
    		}
    		else if (excludeList != null && !excludeList.isEmpty() &&
    				!excludeBy.equalsIgnoreCase("cve_id") && !Helper.isValidQidList(excludeList)){
    			return FormValidation.error("Enter valid QID range/numbers!");
			} else {
				return FormValidation.ok();
			}
    	} catch(Exception e) {
    		return FormValidation.error("Enter valid value!");
    	} 
    } // End of doCheckExcludeList FormValidation
    
    public FormValidation doCheckWebhookUrl(String webhookUrl) {
        try {
        	if(StringUtils.isEmpty(webhookUrl)) {
        		return FormValidation.ok();
        	}
        	Pattern patt = Pattern.compile(WEBHOOK_URL_REGEX);
            Matcher matcher = patt.matcher(webhookUrl);
        	
            if (!(matcher.matches())) {
                return FormValidation.error("Webhook Url is not valid!");
            } else {
                return FormValidation.ok();
            }
        } catch (Exception e) {
            return FormValidation.error(e.getMessage());
        }
    } //end of doCheckWebhookUrl FormValidation
      
    @POST
    public ListBoxModel doFillScannerNameItems(Item item, String apiServer, String credsId, String proxyServer, 
    		String proxyPort, String proxyCredentialsId, boolean useProxy, 
    		boolean useEc2, boolean useHost, Logger logger) {
    	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
    	StandardListBoxModel model = new StandardListBoxModel();
    	JsonObject scannerList = new JsonObject();
    	Option e1 = new Option("Select the scanner appliance", "External");
    	model.add(e1);
    	try {
    		if(filledInputs(apiServer, credsId, useProxy, proxyServer, proxyPort)) {
    			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
    			String server = apiServer != null ? apiServer.trim() : "";            		
    			QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);
    			if(useEc2) {
        			logger.info("Fetching EC2 Scanner Names list ... ");
        			scannerList = client.scannerName(false);
        		} else if(useHost){
        			logger.info("Fetching Scanner Names list ... ");
        			scannerList = client.scannerName(true);
        		} else {
        			logger.info("Fetching Scanner Names list ... ");
        			scannerList = client.scannerName(true);
        		}
    			for (String name : scannerList.keySet()) {    				   				
        			JsonObject jk = scannerList.get(name).getAsJsonObject();
	        		String scanStatus = jk.get("status").getAsString();
	        		String scanAccId = jk.get("accountId").getAsString();
	        		if(useEc2) {
	        			Option e = new Option(name + " (Account Id: " + scanAccId +  " | Status: "+scanStatus+")", name);
	        			model.add(e);
	        		}else {
	        			Option e = new Option(name + " (Status: "+scanStatus+")", name);
	        			model.add(e);
	        		}
        		}        			        		
    		}// End of if        		
    	} catch(Exception e) {    		
    		logger.warning("Error to get scanner list. " + e.getMessage());
    		Option ee = new Option(e.getMessage(), "");
			model.add(ee);
    		//return object;
    	}
    	model.sort(Helper.getOptionItemmsComparator());
    	return model;
    }// End of doFillScannerItems
    
    @POST
    public ListBoxModel doFillOptionProfileItems(Item item, String apiServer, String credsId, 
    		String proxyServer, String proxyPort, String proxyCredentialsId, 
    		boolean useProxy, Logger logger) {
    	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
    	StandardListBoxModel model = new StandardListBoxModel();
    	Set<String> nameList = new HashSet<String>();
    	Option e1 = new Option("Default scan option profile", "Initial Options");
    	model.add(e1);        	
    	try {
    		if(filledInputs(apiServer, credsId, useProxy, proxyServer, proxyPort)) {
    			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
    			String server = apiServer != null ? apiServer.trim() : "";
    			QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);
        		logger.info("Fetching Option Profiles list ... ");
        		nameList = client.optionProfiles();	        		
        		for (String name : nameList) {
        			Option e = new Option(name, name);
        			model.add(e);	        		
        		}	        		
    		}// End of if        		
    	} catch(Exception e) {    		
    		logger.warning("Error to get option profile list. " + e.getMessage());
    		Option ee = new Option(e.getMessage(), "");
			model.add(ee);
    	}        	
    	model.sort(Helper.getOptionItemmsComparator());
    	return model;
    } // End of doFillOptionProfileItems
    
    @POST
    public ListBoxModel doFillEc2ConnDetailsItems(Item item, 
    		String apiServer, String credsId, 
    		String proxyServer, String proxyPort, 
    		String proxyCredentialsId, 
    		boolean useProxy, boolean useEc2, Logger logger) {
    	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
    	StandardListBoxModel model = new StandardListBoxModel();
    	Option e1 = new Option("--select--", "");
    	model.add(e1); 
    	try {        		
    		if(useEc2 && filledInputs(apiServer, credsId, useProxy, proxyServer, proxyPort)) {
    			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
    			String server = apiServer != null ? apiServer.trim() : "";            		
    			QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);    			
    			logger.info("Fetching Ec2 connector name list ... ");	        		
        		ctorNameList = client.getConnector();
        		for (String name : ctorNameList.keySet()) {
        			JsonObject jk = ctorNameList.get(name).getAsJsonObject();	        			
	        		JsonObject ConName = new JsonObject();
	        		JsonObject ConNameDetails = new JsonObject();
	        		String accId = jk.get(awsAccountId).getAsString();
	        		String connectorState = jk.get("connectorState").getAsString();
	        		ConNameDetails.addProperty(awsAccountId, accId);
	        		ConNameDetails.addProperty("id", jk.get("id").getAsString());
	        		ConName.add(name,ConNameDetails);
	        		Option e = new Option(name + " (Account Id:" + accId + " | State:"+connectorState+")", ConName.toString());        			
        			model.add(e);
        		}
    		}// End of if        		
    	} catch(Exception e) {
    		Option e2 = new Option(e.getMessage(), "");
			model.add(e2);			
			logger.warning("There is an error while fetching the connectors list. " + e);
    		return model;
    	}        	
    	model.sort(Helper.getOptionItemmsComparator());
    	return model;
    } // End of doFillEc2ConnNameItems
    
    public boolean filledInputs(String apiServer, String credsId, boolean useProxy, String proxyServer, String proxyPort) {			
    	if(StringUtils.isBlank(credsId)) return false;
		if(useProxy && StringUtils.isBlank(proxyServer)) return false;
    	return true;
    }// End of filledInputs method
}// End of DescriptorImplQualys class