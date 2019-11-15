function showVulnsTable(scanResult){
	var vulns = scanResult.vulnsTable.data;	
	var table = jQuery('#vulnsTable').DataTable({             
		"autoWidth": false, 
		"language": {
    		"emptyTable": "No vulnerabilities found"
		 },
		 "dom": '<"vulns-table-top"l<"custom-filters">>rt<"vulns-table-bottom"ip><"clear">',
        "aaData": vulns,
        "aoColumns":[         
            { "mData": "qid", sDefaultContent :  '-', "width": "6%"},
            { "mData": "title", sDefaultContent :  '-', "width": "15%"},
            { "mData": "cve_id", sDefaultContent :  '-', "width": "15%"},
            { "mData": "severity", sDefaultContent :  '-', "width": "7%"},
            { "mData": "cvss_base", sDefaultContent :  '-', "width": "10%"},
            { "mData": "cvss3_base", sDefaultContent :  '-', "width": "10%"},            
            { "mData": "category", sDefaultContent :  '-', "width": "9%"},
            { "mData": "pci_vuln", sDefaultContent :  '-', "width": "5%"},
            { "mData": "type", sDefaultContent :  '-', "width": "8%"},
            { "mData": "bugtraq_id", sDefaultContent :  '-', "width": "5%"}
        ],
        'aoColumnDefs': [
        	{ "sTitle": "QID", "aTargets": [0], "width": "6%", "className": "center"},
            { "sTitle": "Title", "aTargets": [1], "width": "15%", "className": "center" },    
            { "sTitle": "CVE ID", "aTargets": [2], "width": "15%", "className": "center" },
            { "sTitle": "Severity", "aTargets": [3], "width": "7%", "className": "center"},
            { "sTitle": "CVSSv2 Base Score", "aTargets": [4], "width": "10%", "className": "center"},
            { "sTitle": "CVSSv3 Base Score", "aTargets": [5], "width": "10%", "className": "center"},            
            { "sTitle": "Category", "aTargets": [6], "width": "9%", "className": "center"},
            { "sTitle": "PCI Vuln?", "aTargets": [7], "width": "5%", "className": "center"},
            { "sTitle": "Type", "aTargets": [8], "width": "8%", "className": "center"},            
            { "sTitle": "Bug Traq Id", "aTargets": [9], "width": "5%", "className": "center"}
        ]
    });
	
	 jQuery('#vulnsTable tbody').on('click', 'td.details-control', function () {
	        var tr = jQuery(this).closest('tr');
	        var row = table.row( tr );
	 
	        if ( row.child.isShown() ) {
	            // This row is already open - close it
	            row.child.hide();
	            tr.removeClass('shown');
	        }
	        else {
	            // Open this row
	            row.child( format(row.data()) ).show();
	            tr.addClass('shown');
	        }
	    });
	    
	    jQuery("#vulnsTable tbody").on("click", ".more-cve-records", function(e){
	    	var tr = jQuery(this).closest('tr');
	    	var row = table.row( tr );
	    	row.child( format(row.data()) ).show();
	        tr.addClass('shown');
	        return false;
	    });
	    
	    
	    jQuery(".softwares-custom-filters").html(
	    	'<div class="sev-filter-div">' + 
	    	'<span class="filters-label">Show Only: </span>' + '</div>'+ 
	    	'<ul class="filters-list">' +
	    	'<li><input class="custom-filter-checkbox" type="checkbox" id="sw-patchable" value="sw-patchable">  <label for="sw-patchable" class="checkbox-title"> Patchable  </li>' +
	    	'</ul>' 
	    );
	    jQuery(".custom-filters").html(
	    	'<div class="sev-filter-div">' + 
	    	'<span class="filters-label">Show Only: </span>' + 
	    	'<span class="sev-filter-label" >Severity </span>' + 
	    	'<select class="severity-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="5"> 5 </option>' +
	    	'<option value="4"> 4 </option>' +
	    	'<option value="3"> 3 </option>' +
	    	'<option value="2"> 2 </option>' +
	    	'<option value="1"> 1 </option>' +
	    	'</select>' +
	    	'<span class="sev-filter-label" >PCI Vuln </span>' +
	    	'<select class="pci-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="yes"> Yes </option>' +
	    	'<option value="no"> No </option>' +
	    	'</select>' +
	    	'<span class="sev-filter-label" >Vuln Type </span>' +
	    	'<select class="type-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="Confirmed"> Confirmed </option>' +
	    	'<option value="Potential"> Potential </option>' +
	    	'</select>' +
	    	'</div>'
	    );
	    
	    jQuery(".custom-filters-left").html(
	    	
	    );
	    
	    jQuery('.severity-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(3).search( valueSelected ).draw();
	    });
	    
	    jQuery('.pci-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(7).search( valueSelected ).draw();
	    });  
	    
	    jQuery('.type-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(8).search( valueSelected ).draw();
	    });
}

function drawBuildSummary(reportObject){
	jQuery('#build-status').text((reportObject == "PASSED")? "Success" : "Failed");
	
	if(reportObject === "FAILED"){
		jQuery('#build-status').css('color', 'red');
		jQuery('.status-image').addClass('failed');
		jQuery('.status-image').removeClass('success');
	}else{
		jQuery('#build-status').css('color', 'green');
		jQuery('.status-image').removeClass('failed');
		jQuery('.status-image').addClass('success');
	}
	
	/*jQuery("#image-tags").text("-");
	if(reportObject.imageSummary.hasOwnProperty("Tags") && reportObject.imageSummary.Tags){
		var tags = reportObject.imageSummary.Tags.filter(function (el) { return el != null;	});
		var tagsStr = tags.join(', ');
		jQuery("#image-tags").text(tagsStr);
	}
	
	var size = reportObject.imageSummary.size;
	var sizeStr = bytesToSize(parseInt(size));
	jQuery("#image-size").text(sizeStr);*/
}

function showEvaluationSummary(scanResult){
	var isEvaluationResult = scanResult.isEvaluationResult;
	if(isEvaluationResult === 1){
		var reportObject = scanResult.evaluationResult;
		if(reportObject.qids){
			if(reportObject.qids.configured){
				jQuery("#qid-found .image-scan-status").removeClass("not-configured").addClass(reportObject.qids.result ? "ok" : "fail");
				jQuery("#qid-found .image-scan-status .tooltip-text").html("<b>Configured:</b> "+reportObject.qids.configured + "<br /><b>Found: </b>"+ (reportObject.qids.found ? reportObject.qids.found : "0"));
			}
		}
		if(reportObject.cveIds){
			if(reportObject.cveIds.configured){
				jQuery("#cve-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cveIds.result ? "ok" : "fail");
				jQuery("#cve-found .image-scan-status .tooltip-text").html("<b>Configured:</b> "+reportObject.cveIds.configured + "<br /><b>Found: </b>"+ (reportObject.cveIds.found ? reportObject.cveIds.found : "None"));
			}
		}
		if(reportObject.cvss_base){
			if(reportObject.cvss_base.configured){
				jQuery("#cvss-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cvss_base.result ? "ok" : "fail");
				jQuery("#cvss-found .image-scan-status .tooltip-text").html("<b>Configured:</b> CVSSv2 more than or equal to ("+reportObject.cvss_base.configured + ")<br /><b>Found: </b>"+ (reportObject.cvss_base.found ? reportObject.cvss_base.found : "None"));
			}
		}
		if(reportObject.cvss3_base){
			if(reportObject.cvss3_base.configured){
				jQuery("#cvss-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cvss3_base.result ? "ok" : "fail");
				jQuery("#cvss-found .image-scan-status .tooltip-text").html("<b>Configured:</b> CVSSv3 more than or equal to ("+reportObject.cvss3_base.configured + ")<br /><b>Found: </b>"+ (reportObject.cvss3_base.found ? reportObject.cvss3_base.found : "None"));
			}
		}
		if(reportObject.pci_vuln){
			if(reportObject.pci_vuln.configured){
				jQuery("#pci-found .image-scan-status").removeClass("not-configured").addClass(reportObject.pci_vuln.result ? "ok" : "fail");
				jQuery("#pci-found .image-scan-status .tooltip-text").html("<b>Configured:</b> more than or equal to 1<br /><b>Found: </b>"+ (reportObject.pci_vuln.found ? reportObject.pci_vuln.found : "None"));
			}
		}
		if(reportObject.severities){
			var severityObj = reportObject["severities"];
			for(var i=1; i<=5; i++){
				if(severityObj[i])
					if(!(severityObj[i].configured === null || severityObj[i].configured === -1)){
						jQuery("#sev" + i + "-found .image-scan-status").removeClass("not-configured").addClass(severityObj[i].result ? "ok" : "fail");
						jQuery("#sev" + i + "-found .image-scan-status .tooltip-text").html("<b>Configured:</b> more than or equal to "+severityObj[i].configured + "<br /><b>Found: </b>"+ (severityObj[i].found !== null ? severityObj[i].found : "0"));
					}
			}
		}
		if(reportObject.qids.excluded || reportObject.cveIds.excluded)
			jQuery("#excluded-items").html(reportObject.qids.excluded ? "<b>*Excluded QIDs: </b>" + reportObject.qids.excluded : "<b>*Excluded CVEs: </b>"+ reportObject.cveIds.excluded);
		if(reportObject.potentialVulnsChecked)
			jQuery("#potential-checked").html("<i><b>*</b>Considered potential vulnerabilities.</i>");
	}	
}

function drawCVulnsCharts(scanResults){
	jQuery("#sevCVulns-error").hide();
	jQuery("#sevCVulns").show();
	jQuery("#pie-legend-div-c").show();
	if(scanResults.vulns == "0"){
		jQuery("#sevCVulns").hide();
		jQuery("#pie-legend-div-c").hide();
		jQuery("#sevCVulns-error").show();
	}else{
		var d = scanResults.cVulnsBySev;
//		var d = {"1": 12,"2": 1,"3": 32,"4": 5,"5": 15}
		var count = Array();
		var severity = Array();
		
		var i = 0;
		var total = 0;
		for (var key in d) {
			count[i] = d[key];
		   severity[i] = key;
		   total += count[i]; 
		   i++;
		}
		var options = {
		    //segmentShowStroke: false,
		    animateRotate: true,
		    animateScale: false,
		    percentageInnerCutout: 50,
		    tooltipTemplate: "<%= label %>"
		}
//		var colors = ["#CCFFCC", "#CCFFFF", "#FFFF99", "#FF9934","#FF0A00"];
		var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A","#D61E1C"];
		var labels = count; 
		jQuery("#confTotCount").text(total);
		if(! count.some(el => el !== 0)){
			count = ["1", "1", "1", "1", "1"];
			severity = ["1", "2", "3", "4", "5"];
			labels = ["0", "0", "0", "0", "0"];	
			colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
		}
		
		var c = jQuery("#sevCVulns").get(0);
			var ctx = c.getContext("2d");
		
			var pieData = [
				{
				value: count[4].toString(),
				label: "Sev " + severity[4].toString() + " (" + labels[4] + ")",
				color: colors[4]
				},
				{
				value: count[3].toString(),
				label: "Sev " + severity[3].toString() + " (" + labels[3] + ")",
				color: colors[3]
				},
				{
				value: count[2].toString(),
				label: "Sev " + severity[2].toString() + " (" + labels[2] + ")",
				color: colors[2]
				},
				{
				value: count[1].toString(),
				label: "Sev " + severity[1].toString() + " (" + labels[1] + ")",
				color: colors[1]
				},
				{
				value: count[0].toString(),
				label: "Sev " + severity[0].toString() + " (" + labels[0] + ")",
				color: colors[0]
				}
			];
			
			var chart = new Chart(ctx).Doughnut(pieData,options);		
		jQuery("#pie-legend-div-c").append(chart.generateLegend());
	}
}

function drawPVulnsCharts(scanResults){
	jQuery("#sevPVulns-error").hide();
	jQuery("#sevPVulns").show();
	jQuery("#pie-legend-div-p").show();
	if(scanResults.vulns == "0"){
		jQuery("#sevPVulns").hide();
		jQuery("#pie-legend-div-p").hide();
		jQuery("#sevPVulns-error").show();
	}else{
		var d = scanResults.pVulnsBySev;
//		var d = {"1": 12,"2": 1,"3": 32,"4": 5,"5": 15}
		var count = Array();
		var severity = Array();
		
		var i = 0;
		var total = 0;
		for (var key in d) {
			count[i] = d[key];
		   severity[i] = key;
		   total += count[i]; 
		   i++;
		}
		var options = {
		    //segmentShowStroke: false,
		    animateRotate: true,
		    animateScale: false,
		    percentageInnerCutout: 50,
		    tooltipTemplate: "<%= label %>"
		}
//		var colors = ["#CCFFCC", "#CCFFFF", "#FFFF99", "#FF9934","#FF0A00"];
		var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A","#D61E1C"];
		var labels = count; 
		jQuery("#confTotCount").text(total);
		if(! count.some(el => el !== 0)){
			count = ["1", "1", "1", "1", "1"];
			severity = ["1", "2", "3", "4", "5"];
			labels = ["0", "0", "0", "0", "0"];	
			colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
		}
		
		var c = jQuery("#sevPVulns").get(0);
			var ctx = c.getContext("2d");
		
			var pieData = [
				{
				value: count[4].toString(),
				label: "Sev " + severity[4].toString() + " (" + labels[4] + ")",
				color: colors[4]
				},
				{
				value: count[3].toString(),
				label: "Sev " + severity[3].toString() + " (" + labels[3] + ")",
				color: colors[3]
				},
				{
				value: count[2].toString(),
				label: "Sev " + severity[2].toString() + " (" + labels[2] + ")",
				color: colors[2]
				},
				{
				value: count[1].toString(),
				label: "Sev " + severity[1].toString() + " (" + labels[1] + ")",
				color: colors[1]
				},
				{
				value: count[0].toString(),
				label: "Sev " + severity[0].toString() + " (" + labels[0] + ")",
				color: colors[0]
				}
			];
			
			var chart = new Chart(ctx).Doughnut(pieData,options);		
		jQuery("#pie-legend-div-p").append(chart.generateLegend());
	}
}