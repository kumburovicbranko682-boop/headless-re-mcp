<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:wix="http://schemas.microsoft.com/wix/2006/wi">
  <xsl:output method="xml" indent="yes" />

  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()" />
    </xsl:copy>
  </xsl:template>

  <!-- Per-user components require an HKCU registry value as their key path. -->
  <xsl:template match="wix:File/@KeyPath" />

  <xsl:template match="wix:Component">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()" />
      <RegistryValue xmlns="http://schemas.microsoft.com/wix/2006/wi"
        Root="HKCU"
        Key="Software\HeadlessReMcp\Components"
        Name="{@Id}"
        Type="integer"
        Value="1"
        KeyPath="yes" />
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
