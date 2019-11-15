package com.qualys.plugins.vm.auth;

import hudson.util.Secret;

enum AuthType {
    Basic, OAuth
}

public class QualysAuth {
    private AuthType authType;
    private String server;
    private String username;
    private Secret password;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private boolean useProxy = false;
    private Secret proxyPassword;
    private int proxyPort;

    public QualysAuth () {
        
    }

    public QualysAuth (String server, String oauthKey) {
        this.authType = AuthType.OAuth;
        this.authKey = oauthKey;
    }

    
    
    public void setAuthType(AuthType authType) {
		this.authType = authType;
	}

	public void setServer(String server) {
		this.server = server;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setPassword(Secret password) {
		this.password = password;
	}

	public void setAuthKey(String authKey) {
		this.authKey = authKey;
	}

	public void setProxyServer(String proxyServer) {
		this.proxyServer = proxyServer;
	}

	public void setProxyUsername(String proxyUsername) {
		this.proxyUsername = proxyUsername;
	}

	public void setUseProxy(boolean useProxy) {
		this.useProxy = useProxy;
	}

	public void setProxyPassword(Secret proxyPassword) {
		this.proxyPassword = proxyPassword;
	}

	public void setProxyPort(int proxyPort) {
		this.proxyPort = proxyPort;
	}

	public String getServer() {
    	if (server == null) {
    		return "https://qualysapi.qualys.com";
    	}else {
    		return server;
    	}
    }

    public String getUsername() {
    	if (username == null) {
    		return "";
    	}else {
    		return username;
    	}
    }

    public Secret getPassword() {
    	if (password  == null) {
    		return Secret.fromString("");
    	}else {
    		return password;
    	}
    }
    
    public String getProxyServer() {
    	if (proxyServer == null) {
    		return "";
    	}else {
    		return proxyServer;
    	}
    }

    public String getProxyUsername() {        
        if (proxyUsername == null) {
    		return "";
    	}else {
    		return proxyUsername;
    	}
    }

    public Secret getProxyPassword() {
    	if (proxyPassword == null) {
    		return Secret.fromString("");
    	}else {
    		return proxyPassword;
    	}
    }
    public int getProxyPort() {    	
        return proxyPort;
    }
    public String getAuthKey() {
        return authKey;
    }
    public boolean getUseProxy() {
    	if (useProxy) {
    		return true;
    	}else {
    		return useProxy;
    	}
    }
   
    public void setQualysCredentials(String server, String username, String password) {
    	this.authType = AuthType.Basic;
        this.server = server;
        this.username = username;
        this.password = Secret.fromString(password);
    }
	
	  public void setProxyCredentials(String proxyServer, int proxyPort, String
	  proxyUsername, String proxyPassword, boolean useProxy) { 
		  this.proxyServer = proxyServer;
		  this.proxyPort = proxyPort; 
		  this.useProxy = useProxy;
		  if(proxyUsername != null) {
			  this.proxyUsername = proxyUsername;
		  } else {
			  this.proxyUsername = null;
		  }
		  
		  if(proxyPassword != null) {
			  this.proxyPassword = Secret.fromString(proxyPassword);
		  } else {
			  this.proxyPassword = null;
		  }
	  }
}