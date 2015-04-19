<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0" 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:dp="http://www.datapower.com/extensions" 
    xmlns:dpconfig="http://www.datapower.com/param/config" 
    extension-element-prefixes="dp" exclude-result-prefixes="dp dpconfig">
    <xsl:output method="xml"/>
    
    <!-- ============================================================================= -->
    <!-- == Stylesheet:   DataPower B2B To and From IDs                                -->
    <!-- == Version:      1.0                                                          -->
    <!-- ============================================================================= -->
    <!-- == History:                                                                   -->
    <!-- ==                                                                            -->
    <!-- == Description:  Captures sender and receiver details to custom variables     -->
    <!-- == Returns: N/A                                                               -->
    <!-- ============================================================================= -->
   
    <xsl:template match="/">
   
        <!-- Source Data -->
        <xsl:variable name="from" select="dp:variable('var://service/b2b-partner-from')"/>
        <xsl:variable name="to" select="dp:variable('var://service/b2b-partner-to')"/>
        
        <!-- Write custom variables -->
        <dp:set-variable name="'var://context/message/b2bto'" value="$to"/>
        <dp:set-variable name="'var://context/message/b2bfrom'" value="$from"/>                 
    </xsl:template>
</xsl:stylesheet>