var fs = require('fs');
var path = require('path');
var json2toml = require('@iarna/toml');
var funcs = require('./functions.js');
//const { exec } = require("child_process");
var recursive = require("recursive-readdir");

//getting fullpath of directory
const directoryPath = path.join(__dirname, 'rules');

//trying to read all files inside this directory
recursive(directoryPath,["*.txt","*.md"], function (err, files) {
    
    // error if we are not able to find this directory in some how 
    if (err) {
        return console.log('Unable to scan directory: ' + err);
    } 
    //extracting any field from the toml file example : (tags , integration , metadata , index) without duplication
  /*  for(var j = 0;j<files.length;j++){
        
         data =  fs.readFileSync('./rules/'+files[j]);
         var parsed = toml.parse(data);
       
    }
    console.log(funcs.uniqueArray(integrations));
     for(var j = 0;j<files.length;j++){
        
        data =  fs.readFileSync('./rules/'+files[j]);
        var parsed = toml.parse(data);
    } 
        //extracted tags from all toml files saved on unique tags 

         unique_tags = funcs.uniqueArray(all_techs);

    //printing the array of the fields
        console.log(unique_tags) */



        //main functionality of the script
        for(var j = 0;j<files.length;j++){
        integ = '';

        //reading files from directory each file name is saved on files[j]
         //console.log(path.extname(files[j])); 
         if (path.extname(files[j]) == '.toml'){
         data =  fs.readFileSync(files[j]);
            //data = String(data).replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
         //converting TOML data from the file to JSON
         var parsed = json2toml.parse(data);
        

         //check if there are any integration field to extract some data from it (used for enrichment)
         
        
         //get used technologies from index pattern field (logs-*,winlogbeat-*)
         arrays = funcs.checkUsedTechnologie(parsed.rule.index);
         if(funcs.checkIntegration(parsed)){
            integ = parsed.metadata.integration;
            integ = funcs.convertKeywords(integ);
            arrays.push(integ);
         }

        
        //finaly extracted data which is going to be added to the tags .
        to_be_added = funcs.checkConsidered(arrays,parsed.rule.tags);
        to_be_added.forEach(element => {
            //adding each enrichment element to the tags
            parsed.rule.tags.push(element);
        });

        //each rule that contain Network tag should contain Firewall tag
        if(parsed.rule.tags.includes("Network")){
            parsed.rule.tags.push('Firewall');
        }

        //editing the author name from elastic to Octodet
        parsed.rule.author[0] = "Octodet";

        //saving files on directory you want example here ./result/
        if(parsed.rule.false_positives != undefined){
            parsed.rule.false_positives[0] = parsed.rule.false_positives[0].replace('    ','');
            parsed.rule.false_positives[0] = parsed.rule.false_positives[0].replace('    ','');
            parsed.rule.false_positives[0] = parsed.rule.false_positives[0].replace('    ','');
            parsed.rule.false_positives[0] = parsed.rule.false_positives[0].replace('    ','');
        }

        
      //  console.log(parsed);
        
        if(parsed.rule.index != undefined) {
            for (var q = 0;q < parsed.rule.index.length;q++){

            parsed.rule.index[q] =  funcs.addNameConvention(parsed.rule.index[q],"cipher*");
        }
        }
        


        cous = json2toml.stringify(parsed);
        //console.log(cous);
        // console.log(cous);
         //break;
         funcs.saveTOMLFile(funcs.extractName(path.basename(files[j])),'./result/',cous);
         // console.log(path.basename(files[j]))
        

       
    }
    }



});
// make sure you installed requirements of detection-rules tool 
//if you did not please follow this : 

/*
cd detection-rules
pip install -r requirements.txt
*/

//python 3.8+

/* var url = "http://localhost:5601"
var user = "";
var password = "";
var rules_result_directory = "";
exec("python -m ./detection-rules/detection_rules kibana -ku "+ user + " -kp " + password + " --kibana-url " + url + " upload-rule --directory " + rules_result_directory, (error, stdout, stderr) => {
    if (error) {
        console.log(`error: ${error.message}`);
        return;
    }
    if (stderr) {
        console.log(`stderr: ${stderr}`);
        return;
    }
    console.log(`stdout: ${stdout}`);
});
 */
