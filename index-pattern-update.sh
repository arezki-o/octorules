for rule in $(pwd)/*.toml; do
                     
       rulename=${rule##*/}
       extension="${rulename##*.}"
       filename="${rulename%.*}"
        
       grep -iq $1 $rule   
       if [ $? == 1 ]
       then     
	        #This is for neoleap
                number=`grep -n '^index = \[$' $rule | awk -F: '{print $1}'`
	        if [ ! -z "$number" ]
                then
                    appendn=$(($number +1))
                    sed -i'.original' "${appendn}s/$/\n\"logs-syslog*\",/" $rule 
	        fi

		nu=`grep -n '^index = \[' $rule | awk -F: '{print $1}'`
                if [ ! -z "$nu" ]
                then
                    sed -i'.original' "${nu}s/]$/,\"logs-syslog*\"]/" $rule
                fi
		#End of neoleap part

                lineindex=`grep -n "^index =" $rule | awk -F: '{print $1}'`
                linethreatindex=`grep -n "^threat_index =" $rule | awk -F: '{print $1}'`
                
                perl -i'.original' -pe  "s/\*(?=[\"])/*$1*/g if $. == $lineindex" $rule
                
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
