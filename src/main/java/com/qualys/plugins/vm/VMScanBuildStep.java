/* This file is responsible for the configuration in pipeline setup*/

package com.qualys.plugins.vm;

import java.util.logging.Logger;
import javax.inject.Inject;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.workflow.steps.AbstractStepDescriptorImpl;
import org.jenkinsci.plugins.workflow.steps.AbstractStepImpl;
import org.jenkinsci.plugins.workflow.steps.AbstractSynchronousNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.StepContextParameter;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import com.qualys.plugins.vm.VMScanNotifier;
import com.qualys.plugins.vm.util.Helper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

public class VMScanBuildStep extends AbstractStepImpl {
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
    private String excludeBy;
    private boolean doExclude;    
    private boolean evaluatePotentialVulns = false;
    private boolean failByPci = false;    
    private String webhookUrl;
    static JsonObject ctorNameList = new JsonObject();    
    private final static String SCAN_NAME = "[job_name]_jenkins_build_[build_number]";
	private final static int PROXY_PORT = 80;    
    private final static Logger logger = Helper.getLogger(VMScanBuildStep.class.getName());
    
    /* End of Variable Declaration */
    
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
	
	@DataBoundSetter
	public void setProxyCredentialsId(String proxyCredentialsId) { this.proxyCredentialsId = proxyCredentialsId; }
	
	public String getProxyCredentialsId() { return proxyCredentialsId; }
	
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
	
	/*End of Getter Setters*/
    
	/*Class Constructor*/
	@DataBoundConstructor
    public VMScanBuildStep(String apiServer, String credsId, String hostIp, String ec2ConnDetails, String ec2Id, 
    		String scannerName, String scanName, String optionProfile, String proxyServer, 
    		int proxyPort, String proxyCredentialsId, boolean useProxy, boolean useHost, boolean useEc2,
    		String pollingInterval, String vulnsTimeout, int bySev, boolean failBySev, boolean failByQids, 
    		boolean failByCves, String qidList, String cveList, boolean failByCvss, String byCvss, 
    		String cvssBase, boolean doExclude, String excludeBy, String excludeList, boolean evaluatePotentialVulns, 
    		boolean failByPci,String webhookUrl, boolean runConnector
    		/*,String cvssV2Temporal,String cvssV3Temporal*/) {
        
		this.apiServer = apiServer;
        this.credsId = credsId;        
        this.scanName = scanName;
        this.optionProfile = optionProfile;
        this.scannerName = scannerName;
        
        
        if(useProxy) {
        	this.useProxy = useProxy;
	        this.proxyServer = proxyServer;
	        this.proxyPort = proxyPort;
	        this.proxyCredentialsId = proxyCredentialsId;
        }
                
        if(useHost) {
        	this.useHost = useHost;
        	this.hostIp = hostIp;
        	}
        
        
        if(useEc2) {
        	this.useEc2 = useEc2;
        	this.ec2Id = ec2Id;
	        this.runConnector = runConnector;
	        this.ec2ConnDetails = ec2ConnDetails;	        
	        JsonParser jsonParser = new JsonParser();
    		JsonObject jo = (JsonObject)jsonParser.parse(ec2ConnDetails);    		
    		this.ec2ConnName = jo.keySet().toString().replaceAll("\\[|\\]", "");    		
    		JsonObject i =  jo.get(this.ec2ConnName).getAsJsonObject();    		
    		this.ec2ConnAccountId = i.get("awsAccountId").getAsString();
    		this.ec2ConnId = i.get("id").getAsString();
        }
        
        this.pollingInterval = pollingInterval;
        this.vulnsTimeout = vulnsTimeout;
                
        if(failBySev) {        	
        	this.bySev = bySev;
        	this.failBySev = failBySev;        	
        }        
        
        if(failByQids) {
        	this.failByQids = failByQids;
        	this.qidList = qidList;
        }
        if(failByCves) {
        	this.failByCves = failByCves;
        	this.cveList = cveList;
        }
        if(failByCvss) {
        	this.failByCvss = failByCvss;
        	this.byCvss = byCvss;
        	this.cvssBase = cvssBase;
//        	this.cvssV2Temporal = cvssV2Temporal;        	
//        	this.cvssV3Temporal = cvssV3Temporal;
        }
        
    	if(doExclude) {
    		this.doExclude = doExclude;
    		this.excludeBy = excludeBy;
    		this.excludeList = excludeList;
    	}
    	
    	if(failByPci) {
    		this.failByPci = failByPci;
    	}
    	
    	if(failBySev || failByQids || failByCves || failByCvss || failByPci) {
    		this.evaluatePotentialVulns = evaluatePotentialVulns;    		   		
    	}
    	
    	if(!StringUtils.isBlank(webhookUrl)) {
    		this.webhookUrl = webhookUrl;
    	}
    } // End of Constructor 

	/* 1st Nested class*/
    @SuppressWarnings("deprecation")
	@Extension
    public static final class DescriptorImpl extends AbstractStepDescriptorImpl {
        
        @SuppressWarnings("deprecation")
		public DescriptorImpl() {
            super(VMScanBuildExecution.class);
        }// End of Constructor
        
        DescriptorImplQualys descObject = new DescriptorImplQualys();
        
        @Override
        public String getFunctionName() { return descObject.getFunctionName(); }// End of getFunctionName method

        @Override
        public String getDisplayName() { return descObject.getDisplayName(); }  // End of getDisplayName method
                
        public ListBoxModel doFillBySevItems () {return descObject.doFillBySevItems();} // End of doFillBySev ListBoxModel
        
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
    }// End of DescriptorImpl class

    /* 2nd Nested class*/
    /*This class and the run method will be executed when the user clicks on the "Build Now" link of the Jenkins job on UI. 
     * This is valid for both FreeStyle and Pipeline Jobs.*/
    /*####################################################*/
    @SuppressWarnings("deprecation")
	public static final class VMScanBuildExecution extends AbstractSynchronousNonBlockingStepExecution<String> {
        private static final long serialVersionUID = 1L;
        @Inject
        private transient VMScanBuildStep step;
        @StepContextParameter
        private transient Run run;
        @StepContextParameter
        private transient FilePath ws;
        @StepContextParameter
        private transient Launcher launcher;
        @StepContextParameter
        private transient TaskListener taskListener;

        @Override
        protected String run() throws Exception {
        	VMScanNotifier notifier = new VMScanNotifier(step.getApiServer(), step.getCredsId(),
        			step.useEc2, step.getEc2Id(),step.runConnector, 
        			step.getEc2ConnDetails());
        	notifier.setHostIp(step.getHostIp());
        	notifier.setUseHost(step.getUseHost());
        	notifier.setUseEc2(step.getUseEc2());
        	notifier.setEc2ConnDetails(step.getEc2ConnDetails());
        	notifier.setEc2ConnName(step.getEc2ConnName());
        	notifier.setEc2ConnAccountId(step.getEc2ConnAccountId());
        	notifier.setEc2ConnId(step.getEc2ConnId());
        	notifier.setEc2Id(step.getEc2Id());        	
        	notifier.setRunConnector(step.getRunConnector());
    		notifier.setScanName(step.getScanName());
    		notifier.setScannerName(step.getScannerName()); 
    		notifier.setOptionProfile(step.getOptionProfile());
			notifier.setUseProxy(step.getUseProxy());
    		notifier.setProxyServer(step.getProxyServer());
            notifier.setProxyPort(step.getProxyPort());
            notifier.setProxyCredentialsId(step.getProxyCredentialsId());            
            
            notifier.setFailByQids(step.getFailByQids());
            notifier.setQidList(step.getQidList());
            notifier.setFailByCves(step.getFailByCves());
            notifier.setCveList(step.getCveList());
            notifier.setFailByCvss(step.getFailByCvss());
            notifier.setByCvss(step.getByCvss());
            notifier.setCvssBase(step.getCvssBase());
//            notifier.setCvssV2Temporal(step.getCvssV2Temporal());            
//            notifier.setCvssV3Temporal(step.getCvssV3Temporal());
            
            notifier.setCveList(step.getCveList());
            notifier.setBySev(step.getBySev());            
            notifier.setFailBySev(step.getFailBySev());
            notifier.setExcludeBy(step.getExcludeBy());
            notifier.setDoExclude(step.getDoExclude());
            notifier.setExcludeList(step.getExcludeList());
            notifier.setEvaluatePotentialVulns(step.getEvaluatePotentialVulns());
            notifier.setFailByPci(step.getFailByPci());
            notifier.setWebhookUrl(step.getWebhookUrl());
            
            notifier.setPollingInterval(step.getPollingInterval());
            notifier.setVulnsTimeout(step.getVulnsTimeout());
            
    		notifier.perform(run, ws, launcher, taskListener);
        	
    		return "SUCCESS";
        }// End of run method. This is a Jenkins method. 
    } // End of VMScanBuildExecution class
} // End of VMScanBuildStep class

