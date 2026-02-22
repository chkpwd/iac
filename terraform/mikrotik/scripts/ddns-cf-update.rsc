##  <<  For parameters'details see README.md @ https://github.com/bajodel/mikrotik-cloudflare-dns  >>

## ---- Configuration/Start  -----

# Define here single/multiple Dns Records (FQDNs) with their Zone IDs, Record IDs, and AuthTokens
# (hint: populate at least the first (single record to update), uncomment the second one or create more as needed)
:local ParamVect {
                  "chkpwd.com"={
      "DnsZoneID"="${CloudflareZoneID}";
      "DnsRcrdID"="${CloudflareRecordID}";
      "AuthToken"="${CloudflareAPIKey}";
  };
#                 "_____mywanip2_domain_com_____"={
#     "DnsZoneID"="__Cloudflare_Dns_Zone_ID2____";
#     "DnsRcrdID"="__Cloudflare_Dns_Record_ID2__";
#     "AuthToken"="_Cloudflare_Auth_Key_Token_2_";
# };
}

# [default: false] enable verbose (debug) log messages, by default only changes will be logged
:local VerboseLog false

# [default: false] enable TestMode -> it will only monitor/log Wan IPv4 changes (no Cloudflare DNS update)
:local TestMode false

# [default: false] enable certificate validation for Cloudflare API calls (but before install RootCA used by CF)
:local CertCheck false

## ---- Configuration/End  ----

:global WanIP4Cur
:do {
:local ChkIpResult [:tool fetch url="http://checkip.amazonaws.com/" as-value output=user]
:if ($ChkIpResult->"status" = "finished") do={
  :local WanIP4New [:pick ($ChkIpResult->"data") 0 ( [ :len ($ChkIpResult->"data") ] -1 )]
  :if ($WanIP4New != $WanIP4Cur) do={
    # validate the new retrieved Wan IPv4
    :local WanIPv4IsValid true
    :local WanIP4NewMasked ($WanIP4New&255.255.255.255)
    :if ( :toip $WanIP4New != :toip $WanIP4NewMasked ) do={ :set WanIPv4IsValid true } else={ :set WanIPv4IsValid false }
    # if retrieved Wan IPv4 is valid proceed, skip update and log error if not valid
    :if ($WanIPv4IsValid) do={
      :if ($VerboseLog = true) do={ :log info "[script] New Wan IPv4 is valid ($WanIP4New)" }
      # Wan IP changed (valid and different from previously stored one)
      :log warning "[script] Wan IPv4 changed -> New IPv4: $WanIP4New - Old IPv4: $WanIP4Cur"
      # If not in "Test Mode" proceed with Cloudflare DNS update
      :if ($TestMode = false) do={
        # Loop through each DNS Record Names provided
        :foreach fqdn,params in=$ParamVect do={
          :local DnsRcName $fqdn
          :local DnsZoneID ($params->"DnsZoneID")
          :local DnsRcrdID ($params->"DnsRcrdID")
          :local AuthToken ($params->"AuthToken")
          :if ($VerboseLog = true) do={ :log info "[script] Preparing CF-DNS-Update for <$DnsRcName>" }
          # create API update url for DNS Zone/Record
          :local url "https://api.cloudflare.com/client/v4/zones/$DnsZoneID/dns_records/$DnsRcrdID/"
          :if ($VerboseLog = true) do={ :log info "[script] Generated URL for DNS update: $url" }
          :if ($VerboseLog = true) do={ :log info "[script] Certificate check is globally set to $CertCheck" }
          # evaluating "check-certificate" (yes/no)
          :local CheckYesNo
          :if ($CertCheck = true) do={ :set CheckYesNo "yes" } else={ :set CheckYesNo "no" }
          # updating the DNS Record
          :local CfApiResult [/tool fetch http-method=put mode=https url=$url check-certificate=$CheckYesNo output=user as-value \
          http-header-field="Authorization: Bearer $AuthToken,Content-Type: application/json" \
          http-data="{\"type\":\"A\",\"name\":\"$DnsRcName\",\"content\":\"$WanIP4New\",\"ttl\":1,\"proxied\":true}"]
          if ($CfApiResult->"status" = "finished") do={
            # log success message (log <warning> used just to make it stand out in logs)
            :log warning "[script] Updated Cloudflare DNS record for <$DnsRcName> to $WanIP4New"
          } else={ :log error "[script] Error occurred updating Cloudflare DNS record for <$DnsRcName> to $WanIP4New" }
          # pause a little bit before the next one
          :delay 1
      } }
      # update stored global variable
      :set WanIP4Cur $WanIP4New
    } else={ :log error "[script] Error occurred, retrieved Wan IPv4 is invalid ($WanIP4New)" }
  } else={ :if ($VerboseLog = true) do={ :log info "[script] Wan IPv4 didn't change ($WanIP4New)" } }
} else={ :log error "[script] Error occurred retrieving current Wan IPv4 (status: $ChkIpResult)" }
} on-error={ :log error "[script] Error occurred during Cloudflare DNS update process" }
