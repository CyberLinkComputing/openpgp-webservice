<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet exclude-result-prefixes="dp dpconfig" extension-element-prefixes="dp regexp" version="1.0" xmlns:dp="http://www.datapower.com/extensions" xmlns:dpconfig="http://www.datapower.com/param/config" xmlns:regexp="http://exslt.org/regular-expressions" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

    <!-- ============================================================================= -->
    <!-- == Stylesheet:   DataPower B2B Dynamic                                        -->
    <!-- == Version:      1.0                                                          -->
    <!-- ============================================================================= -->
    <!-- == History:                                                                   -->
    <!-- ==                                                                            -->
    <!-- == Description:  Sets routing variables                                       -->
    <!-- == Returns: N/A                                                               -->
    <!-- ============================================================================= -->


    <xsl:template match="/">
        <xsl:variable name="uri" select="dp:variable('var://service/URI')" />        
        <xsl:variable name="path" select="dp:variable('var://service/URL-in')" />

        <xsl:variable name="beforeSlash">
                <xsl:value-of select="regexp:replace($uri,'^\/([A-Za-z0-9\-]+)\/([A-Za-z0-9\-]+)','','$1')"/>
        </xsl:variable>
        <xsl:variable name="afterSlash">
                <xsl:value-of select="regexp:replace($uri,'^\/([A-Za-z0-9\-]+)\/([A-Za-z0-9\-]+)','','$2')"/>
        </xsl:variable>     
        <xsl:choose>
            <xsl:when test="contains($path, 'http://127.0.0.1:28000')"> 
                <dp:set-variable name="'var://service/b2b-doc-type'" value="binary" />
                <dp:set-variable name="'var://service/b2b-partner-from'" value="$beforeSlash" />
                <dp:set-variable name="'var://service/b2b-partner-to'" value="$afterSlash" />
            </xsl:when>
            <xsl:otherwise>
                <!-- Autodetect -->
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
</xsl:stylesheet>
