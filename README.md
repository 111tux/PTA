# PTA
howto use the script:
- set the execution rights to the script:
  -> chmod +x ./gitpush.sh
- run the script to push:
  -> ./gitpush.sh "comment"
  
modules.cfg:
- name<#>application type<#>number of columns in csv<#>command<#>csv delimiter
- example:
  nikto<#>web<#>7<#>nikto -Display V -o tmp.csv -port $port -Format csv -Tuning 9 -h $ip<#>,

# todo
- maybe 100 columns, or no sqlite?!
- first execute commands from modules.cfg, and then filter the findings with python scripts for no .csv files

