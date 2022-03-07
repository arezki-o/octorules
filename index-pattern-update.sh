#!/bin/bash
for rule in $(pwd)/*.toml; do
                     
       rulename=${rule##*/}
       extension="${rulename##*.}"
       filename="${rulename%.*}"
        
       grep -iq $1 $rule   
       if [ $? == 1 ]
       then
                number=`grep -n '^index = \[$' $rule | awk -F: '{print $1}'`
                appendn=$(($number +1))
                sed "${appendn}s/$/\n\"logs-syslog*\",/" $rule 
                

                lineindex=`grep -n "^index =" $rule | awk -F: '{print $1}'`
                linethreatindex=`grep -n "^threat_index =" $rule | awk -F: '{print $1}'`

                sed -i'.original' "${lineindex}s/\*/&$1*/g" $rule
                
                if diff "$rule" "$rule.original";then
                    sed -i "/^index =/,/\]/{/^index =/n;/\]/!{s/\*/&$1*/g}}" $rule 
                fi

                if [ ! -z "$linethreatindex" ]
                then
                    sed -i "${linethreatindex}s/\*/&$1*/g" $rule
                fi
                rm -f "$rule.original"
        fi
done
