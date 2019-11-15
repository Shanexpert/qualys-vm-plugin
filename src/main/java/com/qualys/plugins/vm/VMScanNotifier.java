/* This file is responsible for the configuration in freestyle setup*/
/* BuildSteps that run after the build is completed. 
Notifier is a kind of Publisher that sends out the outcome of the builds to other systems and humans. 
This marking ensures that notifiers are run after the build result is set to its final value by other Recorders. 
To run even after the build is marked as complete, override needsToRunAfterFinalized to return true. */

package com.qualys.plugins.vm;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import org.apache.commons.lang.StringUtils;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import com.qualys.plugins.vm.auth.QualysAuth;
import com.qualys.plugins.vm.client.QualysVMClient;
import com.qualys.plugins.vm.util.Helper;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.tasks.SimpleBuildStep;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.reflect.TypeToken;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

@Extension
public class VMScanNotifier extends Notifier implements SimpleBuildStep {
/* Variable Declaration */
	
	private String apiServer;
    private String credsId;
    private String hostIp;
    private String ec2Id;
    private String ec2ConnDetails;
    private String ec2ConnName;
    private String ec2ConnAccountId;
    private String ec2ConnId;
    private String scanName;
    private String scannerName;
    private String optionProfile;
    private String proxyServer;
    private int proxyPort;
    private String proxyCredentialsId;
    private boolean useProxy = false;
    private boolean useHost = false;
    private boolean useEc2 = false;
    private boolean runConnector = false;
    private String pluginName = "Qualys Vulnerability Management";    
    private String pollingInterval;
    private String vulnsTimeout;    
    private int bySev;
    private boolean failBySev = false;    
    private String qidList;
    private boolean failByQids = false;    
    private String cveList;
    private boolean failByCves = false;    
    private String byCvss;
    private String cvssBase;
    private boolean failByCvss = false;    
    private String excludeList;
    private static String excludeBy;
    private boolean doExclude;    
    private boolean evaluatePotentialVulns = false;
    private boolean failByPci = false;
    private String webhookUrl;    
    private final static String SCAN_NAME = "[job_name]_jenkins_build_[build_number]";
	private final static int PROXY_PORT = 80;
    private final static Logger logger = Helper.getLogger(VMScanBuildStep.class.getName());
    private static final String xml10pattern = "[^"
            + "\u0009\r\n"
            + "\u0020-\uD7FF"
            + "\uE000-\uFFFD"
            + "\ud800\udc00-\udbff\udfff"
            + "]";
    /* End of Variable Declaration */
    
    /*Getter Setters*/
    
    public VMScanNotifier() { }
    
    /*Getter Setters*/
    
    public String getPollingInterval() {return pollingInterval;}
    @DataBoundSetter
	public void setPollingInterval(String pollingInterval) {this.pollingInterval = pollingInterval;}

	public String getVulnsTimeout() {return vulnsTimeout;}
	@DataBoundSetter
	public void setVulnsTimeout(String vulnsTimeout) {this.vulnsTimeout = vulnsTimeout;}

	public String getApiServer() {return apiServer;}	
	@DataBoundSetter
    public void setApiServer(String apiServer) {
		if (apiServer!=null && apiServer.endsWith("/")) {
			apiServer = apiServer.substring(0, apiServer.length() - 1);
		}
		this.apiServer = apiServer;
    }
	
	public boolean getFailByQids() {return failByQids;}
	@DataBoundSetter
	public void setFailByQids(boolean failByQids) {this.failByQids = failByQids;}
	
	public boolean getFailByCves() {return failByCves;}
	@DataBoundSetter
	public void setFailByCves(boolean failByCves) {this.failByCves = failByCves;}
	
	public boolean getFailByCvss() {return failByCvss;}
	@DataBoundSetter
	public void setFailByCvss(boolean failByCvss) {this.failByCvss = failByCvss;}
	
	public String getByCvss() {return byCvss;}
	@DataBoundSetter
	public void setByCvss(String byCvss) {this.byCvss = byCvss;}
	
	public String getCvssBase() {return cvssBase;}
	@DataBoundSetter
	public void setCvssBase(String cvssBase) {this.cvssBase = cvssBase;}
	
//	public String getCvssV2Temporal() {return cvssV2Temporal;}//
//	@DataBoundSetter
//	public void setCvssV2Temporal(String cvssV2Temporal) {this.cvssV2Temporal = cvssV2Temporal;}
//	
//	public String getCvssV3Temporal() {return cvssV3Temporal;}//
//	@DataBoundSetter
//	public void setCvssV3Temporal(String cvssV3Temporal) {this.cvssV3Temporal = cvssV3Temporal;}

	public String getQidList() {return qidList;}
	@DataBoundSetter
	public void setQidList(String qidList) {this.qidList = qidList;}
	
	public String getCveList() {return cveList;}
	@DataBoundSetter
	public void setCveList(String cveList) {this.cveList = cveList;}
	
	public int getBySev() {return this.bySev;}
	@DataBoundSetter
	public void setBySev(int bySev) {this.bySev = bySev;}
		
	public boolean getFailBySev() {return failBySev;}
	@DataBoundSetter
	public void setFailBySev(boolean failBySev) {this.failBySev = failBySev;}

	public String getCredsId() {return credsId;}
	@DataBoundSetter
	public void setCredsId(String cred) {this.credsId = cred;}

    public String getHostIp() {return hostIp;}
    @DataBoundSetter
	public void setHostIp(String hostIp) {this.hostIp = hostIp;}
    
    public String getEc2Id() {return ec2Id;}    
    @DataBoundSetter
    public void setEc2Id(String ec2Id) {this.ec2Id = ec2Id;}
    
    public String getEc2ConnDetails() {return ec2ConnDetails;}    
    @DataBoundSetter
    public void setEc2ConnDetails(String ec2ConnDetails) {this.ec2ConnDetails = ec2ConnDetails;}
    
    public String getEc2ConnName() {return ec2ConnName;}    
    @DataBoundSetter
    public void setEc2ConnName(String ec2ConnName) {this.ec2ConnName = ec2ConnName;}
    
    public String getEc2ConnAccountId() {return ec2ConnAccountId;}    
    @DataBoundSetter
    public void setEc2ConnAccountId(String ec2ConnAccountId) {this.ec2ConnAccountId = ec2ConnAccountId;}
    
    public String getEc2ConnId() {return ec2ConnId;}    
    @DataBoundSetter
    public void setEc2ConnId(String ec2ConnId) {this.ec2ConnId = ec2ConnId;}    
    
    public boolean getRunConnector() {return runConnector;}
	@DataBoundSetter
	public void setRunConnector(boolean runConnector) {this.runConnector = runConnector;}
    
    public String getScannerName() {return scannerName;}
    @DataBoundSetter
    public void setScannerName(String scannerName) {this.scannerName = scannerName;}

    public String getScanName() {return scanName;}
    @DataBoundSetter
    public void setScanName(String scanName) {
    	scanName = StringUtils.isBlank(scanName) ? SCAN_NAME : scanName;
    	this.scanName = scanName;
    }
    
    public String getOptionProfile() {return optionProfile;}
    @DataBoundSetter
    public void setOptionProfile(String optionProfile) {this.optionProfile = optionProfile;}

    public String getProxyServer() {return proxyServer;}
	@DataBoundSetter
	public void setProxyServer(String proxyServer) {this.proxyServer = proxyServer;}
	
	public int getProxyPort() {return proxyPort;}
	@DataBoundSetter
	public void setProxyPort(int proxyPort) {
		proxyPort = proxyPort <= 0 ? PROXY_PORT : proxyPort;
		this.proxyPort = proxyPort;
	}
	
	public String getProxyCredentialsId() { return proxyCredentialsId; }
	@DataBoundSetter
	public void setProxyCredentialsId(String proxyCredentialsId) { this.proxyCredentialsId = proxyCredentialsId; }
		
	public boolean getUseProxy() {return useProxy;}
	@DataBoundSetter
	public void setUseProxy(boolean useProxy) {this.useProxy = useProxy;}
	
	public boolean getUseHost() {return useHost;}
	@DataBoundSetter
	public void setUseHost(boolean useHost) {this.useHost = useHost;}
	
	public boolean getUseEc2() {return useEc2;}
	@DataBoundSetter
	public void setUseEc2(boolean useEc2) {this.useEc2 = useEc2;}
	
	public boolean getDoExclude() {return doExclude;}
	@DataBoundSetter
    public void setDoExclude(boolean doExclude) {this.doExclude = doExclude;}
    
	public String getExcludeBy() {return excludeBy;}
	@DataBoundSetter
    public void setExcludeBy(String excludeBy) {this.excludeBy = excludeBy;}
	
	public String getExcludeList() {return excludeList;}	
	@DataBoundSetter
    public void setExcludeList(String excludeList) {this.excludeList = excludeList;}
	
	public boolean getEvaluatePotentialVulns() {return evaluatePotentialVulns;}
	@DataBoundSetter
	public void setEvaluatePotentialVulns(boolean evaluatePotentialVulns) {this.evaluatePotentialVulns = evaluatePotentialVulns;}
	
	public boolean getFailByPci() {return failByPci;}
	@DataBoundSetter
	public void setFailByPci(boolean failByPci) {this.failByPci = failByPci;}
	
	public String getWebhookUrl() {return webhookUrl;}
	@DataBoundSetter
    public void setWebhookUrl(String webhookUrl) {this.webhookUrl = webhookUrl;}
	
	public JsonObject getCriteriaAsJsonObject() {
    	JsonObject obj = new JsonObject();
    	
    	JsonObject failConditionsObj = new JsonObject();
    	Gson gson = new Gson();    	
    	if(failByQids) {
	    	if(this.qidList == null || this.qidList.isEmpty()) {
	    		JsonElement empty = new JsonArray();
	    		failConditionsObj.add("qids", empty);
	    	}else {
		    	List<String> qids = Arrays.asList(this.qidList.split(","));
		    	qids.replaceAll(String::trim);
		    	JsonElement element = gson.toJsonTree(qids, new TypeToken<List<String>>() {}.getType());		    	
		    	failConditionsObj.add("qids", element);
	    	}
    	}// end of failByQids
    	
    	if(failByCves) {
	    	if(this.cveList == null || this.cveList.isEmpty()) {
	    		JsonElement empty = new JsonArray();
	    		failConditionsObj.add("cve_id", empty);
	    	}else {
		    	List<String> cve = Arrays.asList(this.cveList.split(","));
		    	cve.replaceAll(String::trim);
		    	JsonElement element = gson.toJsonTree(cve, new TypeToken<List<String>>() {}.getType());
		    	failConditionsObj.add("cve_id", element);
	    	}
    	}// end of failByCves
    	
    	if(failByCvss) {
    		String baseField = this.byCvss;  
    		List<String> cvssCount = new ArrayList<String>();
    		cvssCount.add("0");
    		cvssCount.add("0.0");
    		double cvssBase = (this.cvssBase == null || this.cvssBase.isEmpty() || cvssCount.contains(this.cvssBase)) ? 0.0: Double.parseDouble(this.cvssBase);
    		
	    	if(cvssBase <= 0.0) {
	    		JsonElement empty = new JsonArray();	    		
	    		failConditionsObj.add(baseField, empty);
	    	}else {		    	
		    	failConditionsObj.addProperty(baseField, this.cvssBase);
	    	}
    	} // end of failByCvss
    	if(failBySev){
	    	JsonObject severities = new JsonObject();
	    	if(this.failBySev) {
	    		for(int i = this.bySev ; i <= 5; i++) {    			
	    			severities.addProperty(""+i,1);
	    		}
	    	}    	
	    	failConditionsObj.add("severities", severities);
    	}// end of failBySev
    	
    	if(this.doExclude) {
    		if("cve_id".equals(excludeBy)) {
    			failConditionsObj.addProperty("excludeBy", "cve_id");
    			List<String> cves = Arrays.asList(this.excludeList.split(","));
    	    	JsonElement element = gson.toJsonTree(cves, new TypeToken<List<String>>() {}.getType());
    	    	failConditionsObj.add("excludeCVEs", element);
    		}
    		if("qid".equals(excludeBy)) {
    			failConditionsObj.addProperty("excludeBy", "qid");
    			List<String> qids = Arrays.asList(this.excludeList.split(","));
    	    	JsonElement element = gson.toJsonTree(qids, new TypeToken<List<String>>() {}.getType());
    	    	failConditionsObj.add("excludeQids", element);
    		}    		
    	}
    	
    	if(failByPci) {
    		failConditionsObj.addProperty("failByPci", failByPci);
    	}// end of failByPci
    	
    	failConditionsObj.addProperty("evaluatePotentialVulns", evaluatePotentialVulns);    	
    	
    	obj.add("failConditions",failConditionsObj);    	
    	return obj;
	}// End of getCriteriaAsJsonObject
	
	/* End of Getter Setters*/
	
	/*Class Constructor*/
	 @DataBoundConstructor
	    public VMScanNotifier(String apiServer, String credsId, boolean useEc2, String ec2Id, 
	    		boolean runConnector, String ec2ConnDetails) throws Exception {
	        this.apiServer = apiServer;	        
	        this.credsId = credsId;
	        try {
		        if(useEc2) {
		        	this.useEc2 = useEc2;
		        	this.ec2Id = ec2Id;
			        this.runConnector = runConnector;
			        if(ec2ConnDetails.isEmpty()) {
			        	this.ec2ConnDetails = "{\"NoConnectorSelected\":{\"awsAccountId\":0,\"id\":0,\"connectorState\":0}}";
			        }else {
			        	this.ec2ConnDetails = ec2ConnDetails;
			        }
			        JsonParser jsonParser = new JsonParser();
		    		JsonObject jo = (JsonObject)jsonParser.parse(this.ec2ConnDetails);    		
		    		this.ec2ConnName = jo.keySet().toString().replaceAll("\\[|\\]", "");    		
		    		JsonObject i =  jo.get(this.ec2ConnName).getAsJsonObject();    		
		    		this.ec2ConnAccountId = i.get("awsAccountId").getAsString();
		    		this.ec2ConnId = i.get("id").getAsString();	        
		        }
	        }catch(ClassCastException e) {
	        	throw new ClassCastException("Error occured as the connector is not selected. Error Message: " + e.getMessage());
	        }catch(Exception e) {
	        	throw new Exception("Error Message: " + e.getMessage());
	        }
	    }// end of @DataBoundConstructor
	 
	 /*1st Nested class*/
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {    	
        DescriptorImplQualys descObject = new DescriptorImplQualys();
        
    	@Override
        public String getDisplayName() {
    		return descObject.getFunctionName() + ": " +  descObject.getDisplayName();
        }

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
		}
		public ListBoxModel doFillBySevItems() {return descObject.doFillBySevItems();} // End of doFillBySev ListBoxModel
		
		public FormValidation doCheckApiServer(@QueryParameter String apiServer) {return descObject.doCheckApiServer(apiServer);} // End of doCheckApiServer FormValidation

        public FormValidation doCheckCredsId(@QueryParameter String credsId) {return descObject.doCheckCredsId(credsId);}// End of doCheckCredsId FormValidation
        
        public ListBoxModel doFillCredsIdItems(@AncestorInPath Item item, @QueryParameter String credsId) {return descObject.doFillCredsIdItems(item, credsId);} // End of doFillCredsIdItems FormValidation
        
        public FormValidation doCheckProxyServer(@QueryParameter String proxyServer) {return descObject.doCheckProxyServer(proxyServer);} // End of doCheckProxyServer FormValidation
        
        public FormValidation doCheckProxyPort(@QueryParameter String proxyPort) {return descObject.doCheckProxyPort(proxyPort);} // End of doCheckProxyPort FormValidation
        
        public ListBoxModel doFillProxyCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String proxyCredentialsId) {return descObject.doFillProxyCredentialsIdItems(item, proxyCredentialsId);} // End of doFillProxyCredentialsIdItems FormValidation
        
        public FormValidation doCheckHostIp(@QueryParameter String hostIp) {return descObject.doCheckHostIp(hostIp);} // End of doCheckHostIp FormValidation
 
        public FormValidation doCheckScanName(@QueryParameter String scanName) {return descObject.doCheckScanName(scanName);} // End of doCheckScanName FormValidation     
        
        public FormValidation doCheckEc2Id(@QueryParameter String ec2Id) {return descObject.doCheckEc2Id(ec2Id);} // End of doCheckEc2Id FormValidation
        
        public FormValidation doCheckScannerName(@QueryParameter String scannerName) {return descObject.doCheckScannerName(scannerName);} // End of doCheckScannerName FormValidation
        
        public FormValidation doCheckQidList(@QueryParameter String qidList) {return descObject.doCheckQidList(qidList);} // End of doCheckQidList FormValidation
        
        public FormValidation doCheckCveList(@QueryParameter String cveList) {return descObject.doCheckCveList(cveList);} // End of doCheckCveList FormValidation
        
        public FormValidation doCheckCvssBase(@QueryParameter String cvssBase) {return descObject.doCheckCvssBase(cvssBase);} // End of doCheckCvssBase FormValidation
      
        public FormValidation doCheckPollingInterval(@QueryParameter String pollingInterval) {return descObject.doCheckPollingInterval(pollingInterval);} // End of doCheckPollingInterval FormValidation

        public FormValidation doCheckVulnsTimeout(@QueryParameter String vulnsTimeout) {return descObject.doCheckVulnsTimeout(vulnsTimeout);} // End of doCheckVulnsTimeout FormValidation
        
        public FormValidation doCheckExcludeList(@QueryParameter String excludeList, @QueryParameter String excludeBy) {return descObject.doCheckExcludeList(excludeList, excludeBy);} // End of doCheckExcludeList FormValidation
        
        public FormValidation doCheckWebhookUrl(@QueryParameter String webhookUrl) {return descObject.doCheckWebhookUrl(webhookUrl);} //end of doCheckWebhookUrl FormValidation
        
        public FormValidation doCheckConnection(@QueryParameter String apiServer, @QueryParameter String credsId,
        		@QueryParameter String proxyServer, @QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, @AncestorInPath Item item) {
        	return descObject.doCheckConnection(apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId, useProxy, item);
        } // End of doCheckConnection FormValidation 
       
        public ListBoxModel doFillScannerNameItems(@AncestorInPath Item item, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, 
        		@QueryParameter boolean useEc2, @QueryParameter boolean useHost) {
        	return descObject.doFillScannerNameItems(item, apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId, useProxy, useEc2, useHost, logger);
        }// End of doFillScannerItems ListBoxModel
        
        public ListBoxModel doFillOptionProfileItems(@AncestorInPath Item item, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy) {
        	return descObject.doFillOptionProfileItems(item, apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId, useProxy, logger);
        } // End of doFillOptionProfileItems ListBoxModel
        
        public ListBoxModel doFillEc2ConnDetailsItems(@AncestorInPath Item item, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, @QueryParameter boolean useEc2) {
        	return descObject.doFillEc2ConnDetailsItems(item, apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId, useProxy, useEc2, logger);
        } // End of doFillEc2ConnNameItems ListBoxModel
    }
	/* End of DescriptorImpl class */
    
    /*From this point the Scan Run process is starts.
     * The VMScanLauncher class will be used here.*/
    /*######################################*/
    
    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }
    
    public String getPluginVersion() {
    	try {
     	   MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model;
            if ((new File("pom.xml")).exists())
              model = reader.read(new FileReader("pom.xml"));
            else
              model = reader.read(
                new InputStreamReader(
                		VMScanNotifier.class.getResourceAsStream(
                    "/META-INF/maven/com.qualys.plugins/qualys-vm-scan/pom.xml"
                  )
                )
              );
            return model.getVersion();
        }catch(Exception e) {
     	   logger.info("Exception while reading plugin version; Reason :" + e.getMessage());
     	   return "unknown";
        }
	}//end of getPluginVersion method
   
    /* This method is used inside the nested class VMScanBuildExecution in VMScanVBuildSteps class*/
    //This is called by freestyle Job
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws AbortException {
    	long startTime = System.currentTimeMillis();    	
    	Result r = build.getResult();
        String result = r.toString();
        logger.info("Triggered build #" + build.number);
    	try {
    		String version = getPluginVersion();
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) +" "+pluginName+" plugin(version-"+ version +") started.");
    		logger.info(pluginName+" plugin(version-"+ version +") started.");
    	}catch(Exception e) {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) +" "+pluginName+" plugin started.");
    		logger.info(pluginName+" plugin started.");
    	}
    	listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " "+pluginName+" task - Started.");
    	logger.info(pluginName+" task - started.");
        if (result.equals("SUCCESS")) {
        	if ((useHost && StringUtils.isNotBlank(hostIp)) || (useEc2 && StringUtils.isNotBlank(ec2Id))) {
	            try {
	            	Item project = build.getProject();
	            	launchHostScan(build, listener, project);
	            } catch (Exception e) {	
	            	if(e.toString().equalsIgnoreCase("java.lang.Exception")) {
	            		throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Exception in "+pluginName+" scan result. Finishing the build.");  
	            	 }else if (e.getMessage().equalsIgnoreCase("sleep interrupted")) {	            		 
	                	 logger.log(Level.SEVERE,"Error: User Aborted");                	 
	                	 throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Exception in "+pluginName+" scan result: User Aborted");
	            	 }else {
	                	 logger.log(Level.SEVERE,"Error: "+e.getMessage());            	 
	                	 throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Exception in "+pluginName+" scan result: Finishing the build. Reason:\n" + e.getMessage());
	            	 }                 
	             }finally {
	            	 long endTime = System.currentTimeMillis();
	            	 long time = endTime - startTime;
	            	 listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Total time taken to complete the build: " + Helper.longToTime(time));
	            	 logger.info("Total time taken to complete the build: " + Helper.longToTime(time)); 
	             }
	       } else {
	    	   listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " No Host IP or EC2 Instance Id Configured.");
	    	   throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Host IP or EC2 Instance Id can't be set to null or empty.");
	      }
	   }else {
           listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Since the build is not successful, will not launch "+pluginName+" scan.");
       }
       return true;
    }
    
    //This is called by pipeline Job
    @SuppressWarnings("null")
	@Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath filePath, @Nonnull Launcher launcher, @Nonnull TaskListener taskListener) throws InterruptedException, IOException {    	
    	long startTime = System.currentTimeMillis();
    	Item project = null;
    	logger.info("Triggered build #" + run.number);
    	try {
    		String version = getPluginVersion();
    		taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) +" " +pluginName+" plugin(version-"+ version +") started.");
    		logger.info(pluginName+" plugin(version-"+ version +") started.");
    	}catch(Exception e) {
    		taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) +" " +pluginName+" plugin started.");
    		logger.info(pluginName+" plugin started.");    		
    	}
    	taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " "+pluginName+" scan task - Started.");
    	
    	if ((useHost && StringUtils.isNotBlank(hostIp)) || (useEc2 && StringUtils.isNotBlank(ec2Id))) {
             try {
            	 project = run.getParent();            	            	 
            	 launchHostScan(run, taskListener, project);
             } catch (Exception e) {
            	 if(e.toString().equalsIgnoreCase("java.lang.Exception")) {
            		 throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Exception in "+pluginName+" scan result. Finishing the build."); 
            	 }else if (e.getMessage().equalsIgnoreCase("sleep interrupted")) {
                	 logger.log(Level.SEVERE,"Error: User Aborted");                	 
                     throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Exception in "+pluginName+" scan result: User Aborted"); 
            	 }else {
                	 logger.log(Level.SEVERE,"Error: "+e.getMessage());            	 
                     throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Exception in "+pluginName+" scan result: Finishing the build. Reason:\n" + e.getMessage());            		 
            	 }                 
             }finally {
            	 long endTime = System.currentTimeMillis();
            	 long time = endTime - startTime;	            	 
            	 taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Total time taken to complete the build: " + Helper.longToTime(time));
            	 logger.info("Total time taken to complete the build: " + Helper.longToTime(time)); 
             }
        } else {
        	taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " No Host IP or EC2 Instance Id Configured.");
        	throw new AbortException(new Timestamp(System.currentTimeMillis()) + " Host IP or EC2 Instance Id can't be set to null or empty.");
        }    	
        return;
    }// End of perform method

	public void launchHostScan(Run<?, ?> run, TaskListener listener, Item project) throws Exception {    	 	
    	// Set username and password for the portal		
    	JsonObject connectorState = new JsonObject();
    	connectorState.addProperty("state", true);
    	JsonObject instanceState = new JsonObject();
    	instanceState.addProperty("endpoint", "Unknown");
    	Helper h = new Helper();
    	QualysAuth auth = new QualysAuth();
    	boolean isFailConditionsConfigured = false;
    	String instanceStatus = new String();
    	
    	QualysVMClient client = h.getClient(useProxy, apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId, project);
    	try {
    		String log = " Testing connection with Qualys API Server...";
    		String log1 = " Test connection successful.";
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + log);
    		logger.info(log);
    		client.testConnection();
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + log1);
    		logger.info(log1);
    	}catch(Exception e) {
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Test connection failed. Reason: " + e.getMessage());
    		throw new Exception(e.getMessage());
    	}//end of test connection
    	try {
	    	// check if Fail conditions are configured or not for the scan.	    	   	
	    	if(failByQids || failByCves || failByCvss || this.failBySev || this.failByPci) {
	    		isFailConditionsConfigured = true;
	    	}
    	}catch(Exception e) {
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while setting fail conditions. Reason: " + e.getMessage());
    		throw new Exception(e.getMessage());
    	}//end of setting the Fail Conditions
    	
    	try {
    		auth = h.getQualysAuth(useProxy, apiServer, credsId, proxyServer,
    				proxyPort, proxyCredentialsId, project);			
    	}catch(Exception e) {
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while setting Qualys Credentials. Reason: " + e.getMessage());
    		throw new Exception(e.getMessage());
    	}//end of setting Qualys Credentials
    	
    	try {
	    	if (useEc2) {    		
	    		VMScanEc2ConnectorLauncher ctor = new VMScanEc2ConnectorLauncher(run, listener,    				
	        			pollingInterval,vulnsTimeout, auth,useEc2, this.ec2ConnId, this.ec2ConnName);
	    		// Get instance state and endpoint
	    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Checking the state of instance(" + this.ec2Id+ ") with instance account(" + this.ec2ConnAccountId+ ")");	    		
	    		// Get state of Instance
	    		instanceState = ctor.checkInstanceState(this.ec2Id, this.ec2ConnAccountId);
	    		instanceStatus = instanceState.get("instanceState").getAsString();	    		
	    		
	    		if (instanceState.get("count").getAsInt() == 0) {
		    		// Get state of connector
		    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Checking the state of connector: " + this.ec2ConnName);
		    		String ec2ConnState = ctor.getCtorStatus(this.ec2ConnId, true);	    		
	    		
		    		// log message for checkbox status
	    			String logMsg = " Run connector checkbox: " +( runConnector ? "checked" : "unchecked");
	    			logger.info(logMsg);
	    			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + logMsg);	    			
		    		    		
		    		//If checkbox is checked, decide weather to run the connector depending upon the connector state and instance state
	    			if(!runConnector && !instanceStatus.equalsIgnoreCase("RUNNING")){
	    				// If check box is not check and instance is not running, abort the build 
	    				throw new Exception(new Timestamp(System.currentTimeMillis()) + " Instance state is: "+instanceStatus+". Aborting!!");
	    			} else if(runConnector && runCtorDecision(ec2ConnState, listener)) {
	    				//if the connector is not in ENDING/PROCESSING/QUEUED/RUNNING, run connector	
	    				logger.info(pluginName+" task - Started running the Ec2 Connector: " + ec2ConnName);
		    			ctor.runCtor();
		        		logger.info(pluginName+" task - Finished running Ec2 Connector: " + ec2ConnName);
		    		} else if(runConnector && !runCtorDecision(ec2ConnState, listener)) {
		    			//if the connector is in PENDING/PROCESSING/QUEUED/RUNNING, do polling	    	    	
		    			ctor.ctorPolling(ec2ConnId, false);
		    		}
	    		}
	    	}// end of checking if EC2 is selected
    	}catch(Exception e) {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while checking ec2 details. Reason: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		throw new Exception(e.getMessage());
    	}//end of checking ec2 details
    	
    	try {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " "+pluginName+" scan task - Started.");
    		logger.info(pluginName+" scan task - Started.");    		
    		VMScanLauncher launcher = new VMScanLauncher(run, listener, hostIp, ec2Id, ec2ConnName, 
    				instanceState.get("endpoint").getAsString(), 
        			scannerName, scanName, optionProfile, isFailConditionsConfigured, pollingInterval, 
        			vulnsTimeout, getCriteriaAsJsonObject(), useHost, useEc2, 
        			auth, webhookUrl, byCvss);    		
        	
        	launcher.getAndProcessLaunchScanResult();    	
            listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " "+pluginName+" scan task - Finished.");        
            logger.info(pluginName+" task - Finished.");
    	}catch(NullPointerException e) {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while launching the scan. Could not find the provided instance ID with a given EC2 configuration. The user might have provided the wrong instance/connector/scanner details. Re-check EC2 details provided for the scan.\nAborting the build!!!");    		
    		throw new Exception(e.getMessage());
    	}catch(Exception e) {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Build stopped. Reason: " + e.getMessage());    		 
    		throw new Exception(e.getMessage());
    	}//end of launching the scan
    } // End of launchHostScan method
	
	public boolean runCtorDecision(String ec2ConnState, TaskListener listener) throws Exception {
		boolean run = false;
		List<String> conRunList = new ArrayList<String>();
    	List<String> conNoRunList = new ArrayList<String>();
    	conRunList.add("FINISHED_ERRORS");
    	conRunList.add("ERROR");    	
    	conRunList.add("INCOMPLETE");
    	conRunList.add("FINISHED_SUCCESS");
    	conRunList.add("SUCCESS");
    	conNoRunList.add("RUNNING");
    	conNoRunList.add("PENDING");
    	conNoRunList.add("QUEUED");
    	conNoRunList.add("PROCESSING");    	
    	
    	if (ec2ConnState.equalsIgnoreCase("DISABLED")) {
    		logger.warning("Connector is in "+ec2ConnState+" state. Aborting!!");
			throw new Exception("Connector is in "+ec2ConnState+" state. Aborting!!");			
		}else if (conNoRunList.contains(ec2ConnState)) {
			logger.warning("Connector state is "+ec2ConnState+". Not running the connector!");
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Connector state is "+ec2ConnState+". Not running the connector!");
			run = false;
		} else if(conRunList.contains(ec2ConnState)) {
			logger.warning("Connector state is "+ec2ConnState+". Running the connector!");
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Connector state is "+ec2ConnState+". Running the connector!");
			run =  true;
		}
		return run;
	}
} // End of VMScanNotifier class