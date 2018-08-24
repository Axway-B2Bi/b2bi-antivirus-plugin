package com.axway.antivirus.configuration;

import com.axway.util.StringUtil;

import com.sun.org.apache.xpath.internal.operations.Bool;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNull;

public class ValidateConfigurationTest
{
	private static AntivirusConfigurationManager avConfManager;
	private static AntivirusConfigurationHolder avConfHolder;
	private static String pathToConfFile;
	private static String pathToNewConfFile;

	@Before
	public void setUp()
	{
		pathToConfFile = Paths.get(".").toAbsolutePath().normalize().toString()
			+ "\\src\\test\\java\\resources\\avScanner.properties";
		pathToNewConfFile = Paths.get(".").toAbsolutePath().normalize().toString()
			+ "\\src\\test\\java\\resources\\avScanner2.properties";

		avConfManager = AntivirusConfigurationManager.getInstance();
		avConfHolder = avConfManager.getScannerConfiguration(pathToConfFile);
	}

	public File makeFile(String property, String propertyValue) throws IOException
	{
		File propsFile = new File(pathToNewConfFile);
		Map<String, String> contents = new HashMap<>();
		contents.put("hostname", "antivirusID.hostname=");
		contents.put("port", "antivirusID.port=");
		contents.put("service", "antivirusID.service=");
		contents.put("ICAPServerVersion", "antivirusID.ICAPServerVersion=");
		contents.put("previewSize", "antivirusID.previewSize=");
		contents.put("stdSendLength", "antivirusID.stdSendLength=");
		contents.put("stdReceiveLength", "antivirusID.stdReceiveLength=");
		contents.put("connectionTimeout", "antivirusID.connectionTimeout=");
		contents.put("rejectFileOnError", "antivirusID.rejectFileOnError=");
		contents.put("scanFromIntegrator", "antivirusID.scanFromIntegrator=");
		contents.put("maxFileSize", "antivirusID.maxFileSize=");
		contents.put("fileNameRestriction", "antivirusID.fileNameRestriction=");
		contents.put("fileExtensionRestriction", "antivirusID.fileExtensionRestriction=");
		contents.put("protocolRestriction", "antivirusID.protocolRestriction=");
		contents.put("partnerNameRestriction", "antivirusID.partnerNameRestriction=");

		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(propsFile)));
		for (Map.Entry<String, String> entry : contents.entrySet())
			if (entry.getKey().equalsIgnoreCase(property))

			{
				writer.write(entry.getValue());
				writer.write(propertyValue);
				writer.newLine();
			}
			else
			{
				writer.write(entry.getValue());
				StringBuilder sb;
				switch (entry.getKey())
				{
					case "hostname":
						writer.write(avConfHolder.getHostname());
						break;
					case "port":
						writer.write(String.valueOf(avConfHolder.getPort()));
						break;
					case "service":
						writer.write(avConfHolder.getService());
						break;
					case "ICAPServerVersion":
						writer.write(avConfHolder.getServerVersion());
						break;
					case "previewSize":
						writer.write(String.valueOf(avConfHolder.getPreviewSize()));
						break;
					case "stdSendLength":
						writer.write(String.valueOf(avConfHolder.getStdSendLength()));
						break;
					case "stdReceiveLength":
						writer.write(String.valueOf(avConfHolder.getStdReceiveLength()));
						break;
					case "connectionTimeout":
						writer.write(String.valueOf(avConfHolder.getConnectionTimeout()));
						break;
					case "rejectFileOnError":
						writer.write(String.valueOf(avConfHolder.isRejectFileOnError()));
						break;
					case "scanFromIntegrator":
						writer.write(String.valueOf(avConfHolder.isScanFromIntegrator()));
						break;
					case "maxFileSize":
						writer.write(String.valueOf(avConfHolder.getMaxFileSize()));
						break;
					case "fileNameRestriction":
						List<String> fileNameRestrictions = avConfHolder.getFilenameRestrictions();
						sb = new StringBuilder();
						if (!fileNameRestrictions.isEmpty())
							for (String fnRestr : fileNameRestrictions)
								sb.append(fnRestr + ",");
						if (sb.toString().length() > 0)
							writer.write(sb.toString().substring(0, sb.length() - 1));
						break;
					case "fileExtensionRestriction":
						List<String> fileExtensionRestrictions = avConfHolder.getFileExtensionRestriction();
						sb = new StringBuilder();
						if (!fileExtensionRestrictions.isEmpty())
							for (String feRestr : fileExtensionRestrictions)
								sb.append(feRestr + ",");
						if (sb.toString().length() > 0)
							writer.write(sb.toString().substring(0, sb.length() - 1));
						break;
					case "protocolRestriction":
						List<String> protocolRestrictions = avConfHolder.getProtocolRestrictions();
						sb = new StringBuilder();
						if (!protocolRestrictions.isEmpty())
							for (String prRestr : protocolRestrictions)
								sb.append(prRestr + ",");
						if (sb.toString().length() > 0)
							writer.write(sb.toString().substring(0, sb.length() - 1));
						break;
					case "partnerNameRestriction":
						List<String> partnerNameRestrictions = avConfHolder.getRestrictedPartners();
						sb = new StringBuilder();
						if (!partnerNameRestrictions.isEmpty())
							for (String pnRestr : partnerNameRestrictions)
								sb.append(pnRestr + ",");
						if (sb.toString().length() > 0)
							writer.write(sb.toString().substring(0, sb.length() - 1));
						break;
				}
				writer.newLine();
			}

		writer.close();
		return propsFile;
	}

	@Test
	public void noPortTest() throws IOException
	{
		File propFile = makeFile("port", "");
		avConfManager.setConfLoaded(Boolean.valueOf("false"));
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noHostnameTest() throws IOException
	{
		File propFile = makeFile("hostname", "");
		avConfManager.setConfLoaded(Boolean.valueOf("false"));
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noPartnerRestrictionsTest() throws IOException
	{
		File propFile = makeFile("partnerNameRestriction", "");
		avConfManager.setConfLoaded(Boolean.valueOf("false"));
		assertEquals(0, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getRestrictedPartners().size());
	}

	@Test
	public void noConnectionTimeoutTest() throws IOException
	{
		File propFile = makeFile("connectionTimeout", "");
		avConfManager.setConfLoaded(Boolean.valueOf("false"));
		//if no connection timeout is specified, the default value <10000> is returned
		assertEquals(10000, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getConnectionTimeout());
	}
}
