<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet
 version="2.0"
 xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<!--
$Id: symagent_config.xsl 1 2008-01-10 18:37:05Z smoot $
AgentSDK - configuration

Dan CAMPER dan@bti.net
Paco NATHAN paco@symbiot.com

@LICENSE@
 -->

<xsl:output
 method="xml"
 omit-xml-declaration="no"
 indent="yes"
/>
<xsl:strip-space
 elements="*"
/>


<xsl:param
 name="config_basedir"
/>
<xsl:param
 name="log_dir"
/>
<xsl:param
 name="webapp_name"
/>
<xsl:param
 name="agent_port"
/>


<xsl:template
 match="HOST"
>
<xsl:comment>AgentSDK configuration</xsl:comment>

<preferences
 where="local"
 version="1.0"
>
<certificates_dir>
<xsl:value-of
 select="$config_basedir"
/>
<xsl:text>/certs</xsl:text>
</certificates_dir>

<logging>

<directory>
<xsl:value-of
 select="$log_dir"
/>
</directory>

<user>
</user>

</logging>
<server>
    
<host>
<xsl:value-of
 select="INTERFACE[@selected = 'true']/@ip_addr"
/>
<xsl:text>/</xsl:text>
<xsl:value-of
 select="$webapp_name"
/>
<xsl:text>/agent</xsl:text>
</host>
    
<port>
<xsl:text>80</xsl:text>
</port>

<ssl_port>
<xsl:value-of
 select="$agent_port"
/>
</ssl_port>

</server>
</preferences>
</xsl:template>

</xsl:stylesheet>
