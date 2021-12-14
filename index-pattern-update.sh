for rule in *.toml; do
        
        match=`grep $1 $rule`
        
        if [ ! -z "$match" ]
        then
           echo "The rule has not been altered"
        else
           echo "The rule already contains:" $1
        fi        
        
        rulename=${rule##*/}
        #echo "The rule name is : "$rulename
        
        extension="${rulename##*.}"
        #echo "The rule name extension is: "$extension
        
        filename="${rulename%.*}"
        #echo "The filename without extension is: "$filename

        lineindex=`grep -n "^index =" $rule | awk -F: '{print $1}'`
        echo "The lineindex is: "$lineindex "+" $rulename
        
        linethreatindex=`grep -n "^threat_index =" $rule | awk -F: '{print $1}'`

        sed -i'.original' "${line}s/\*/&$1*/g" $rule

        if [ ! -z "$linethreatindex" ]
        then
           # echo "The linethreatindex is: "$linethreatindex "+" $rulename

        sed -i'.original' "${linethreatindex}s/\*/&$1*/g" $rule
        fi
done
