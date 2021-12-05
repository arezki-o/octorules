var fs = require('fs');
module.exports = {
//checkFor functions : check technologie of each index pattern example index = winlogbeat-* only checkForWinLogBeat returns true
    addNameConvention : function(index_pattern,name_conve){
	return index_pattern+'-'+name_conve;
	},
    //check for elastic agent index patterns 
    checkForElasticAgent : function (index){
        substring = "logs";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for logstash index pattern
    checkForLogstash : function (index){
        substring = "logstash";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for filebeat index pattern
    checkForFileBeat :  function (index){
    substring = "filebeat";
    checker = false;
    if(index != undefined){
        for (i = 0; i<index.length;i++){
            string = index[i];
            if(string.includes(substring)){
                checker = true;
                break;
        }
          }
    }
    return checker;
    },

    //check for winlogbeat index pattern
    checkForWinLogBeat : function (index){
        substring = "winlogbeat";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
    
        return checker;
    },

    //check for packetbeat index pattern
    checkForPacketBeat : function (index){
        substring = "packetbeat";
        checker = false;
        
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for metricbeat index pattern
    checkForMetricBeat : function (index){
        substring = "metrics";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for heartbeat index pattern
    checkForHeartBeat : function (index){
        substring = "heartbeat";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for auditbeat index pattern
    checkForAuditBeat : function (index){
        substring = "auditbeat";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for functionbeat index pattern
    checkForFunctionBeat : function (index){
        substring = "functionbeat";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for apm index pattern
    checkForApm : function (index){
        substring = "apm";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring) || string.includes("traces")){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for aws index pattern
    checkForAws : function (index){
        substring = "aws";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for okta index pattern
    checkForOkta : function (index){
        substring = "okta";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for azure index pattern
    checkForAzure : function (index){
        substring = "azure";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for o365 index pattern
    checkForO365 : function (index){
        substring = "o365";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for engame index pattern
    checkForEndGame : function (index){
        substring = "endgame";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for google workspace index pattern
    checkForGoogleWorkspace : function (index){
        substring = "google_workspace";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for endpoint Security index pattern
    checkForEndpointSecurity : function (index){
        substring = "endpoint";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check for gcp index pattern
    checkForGCP : function (index){
        substring = "GCP";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },
    
    //check for cyberarkpas index pattern
    checkForCyberArkpas : function (index){
        substring = "cyberarkpas";
        checker = false;
        if(index != undefined){
            for (i = 0; i<index.length;i++){
                string = index[i];
                if(string.includes(substring)){
                    checker = true;
                    break;
            }
              }
        }
        return checker;
    },

    //check if it is a machine learning rule or not
    checkIfML : function (type){
        result = (type == 'machine_learning') ?  true : false;
        return result;
        
    },

    //get data of each field from parsed TOML file example tag field 
    getDataOfFieldsFromParsedTOML : function(field,parsed,all_techs){
        fields = parsed.rule[field];
        
        for (let i = 0; i < fields.length; i++) {
            all_techs.push(fields[i]);
            
        }
        
         
    },

    //delete duplicates from any array
    uniqueArray : function(array){
        uniq = [...new Set(array)];
       
        return uniq;
    },

    //check if the enrichment that we are going to add it already exists in tags field and return only the one which does not exist
    checkConsidered : function(techs,tags){
        not_matched = [];
        intersection = tags.filter(element => techs.includes(element));
        intersection.forEach(element => {
            this.removeItem(techs,element);
        });
        
        return techs;
    },

    //remove item from array by item value
    removeItem : function (array, item) {
        var i = array.length;
    
        while (i--) {
            if (array[i] === item) {
                array.splice(array.indexOf(item), 1);
            }
        }
    },

    //convert gathered keywords from integrations to the main keywords used in elastic exp : (google_workspace => Google Workspace)
    convertKeywords : function (keyword){
        if(keyword == 'aws'){
            return 'AWS';
        }
        if(keyword == 'okta'){
            return 'Okta';
        }
        if(keyword == 'google_workspace'){
            return 'Google Workspace';
        }
        if(keyword == 'gcp'){
            return 'GCP';
        }
        if(keyword == 'o365'){
            return 'Microsoft 365';
        }
        if(keyword == 'azure'){
            return 'Azure';
        }
        if(keyword == 'endpoint'){
            return "Endpoint Security";
        }
        if(keyword == 'cyberarkpas'){
            return 'cyberarkpas';
        }
    },

    //saving toml data into files by file name and directory
    saveTOMLFile : function(name,directory = './result/',data){
      console.log(directory+''+name+'.toml')  
      

     if (!fs.existsSync(directory)){
      fs.mkdirSync(directory);
      fs.writeFile(directory+''+name+'.toml', data,()=>{
         });
     }else{
        fs.writeFile(directory+''+name+'.toml', data,()=>{ });
 
       }
     
    },

    //extract file name without extension
    extractName : function(filename){
        return filename.split('.').slice(0, -1).join('.');
    },

    //get the used technologies from index pattern return in techs array exp : (filebeat-*) techs.push(FileBeat)
    checkUsedTechnologie : function (index){
        var techs = [];
     if(this.checkForFileBeat(index)){
        techs.push("FileBeat")
     }
    
     if(this.checkForWinLogBeat(index)){
       techs.push("WinLogBeat");
     }
     
     if(this.checkForPacketBeat(index)){
         techs.push("PacketBeat")
     }
    
     if(this.checkForMetricBeat(index)){
        techs.push("MetricBeat")
    }
    
    if(this.checkForHeartBeat(index)){
        techs.push("HeartBeat")
    }
    
    if(this.checkForAuditBeat(index)){
        techs.push("AuditBeat")
    }
    
    if(this.checkForFunctionBeat(index)){
        techs.push("FunctionBeat")
    }
    
    if(this.checkForElasticAgent(index)){
        techs.push("Elastic-Agent")
    }
    
    if(this.checkForLogstash(index)){
        techs.push("Logstash")
    }
    
    if(this.checkForO365(index)){
        techs.push("Microsoft 365")
    }
    
    if(this.checkForOkta(index)){
        techs.push("Okta")
    }
    
    if(this.checkForAws(index)){
        techs.push("AWS")
    }
    
    if(this.checkForApm(index)){
        techs.push("APM")
    }
    
    if(this.checkForEndGame(index)){
        techs.push("Elastic Endgame")
    }
    
    if(this.checkForAzure(index)){
        techs.push("Azure")
    }
    
    if(this.checkForGoogleWorkspace(index)){
        techs.push("Google Workspace")
    }
    
    
    if(this.checkForEndpointSecurity(index)){
        techs.push("Endpoint Security")
    }
    
    if(this.checkForCyberArkpas(index)){
        techs.push("cyberarkpas")
    }
    
    if(this.checkForGCP(index)){
        techs.push("GCP");
    }
    return techs;
    },

    //check if the integration field exist in the rule or not.
     checkIntegration : function(parsed){
        if (parsed.metadata.integration == undefined){
            return false;
        }else{
            return true;
        }
    
    }
}
