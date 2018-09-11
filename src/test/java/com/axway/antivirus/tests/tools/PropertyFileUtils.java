package com.axway.antivirus.tests.tools;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PropertyFileUtils
{
	private static AntivirusConfigurationHolder avTemplateConfHolder;
	private static String pathToTemplateFile;
	private static String pathToGeneratedFile;

	private static String icapInputFilesFolderPath;

	public PropertyFileUtils()
	{
		this.pathToTemplateFile =
			Paths.get(".").toAbsolutePath().normalize().toString() + File.separator + "src" + File.separator + "test"
				+ File.separator + "resources" + File.separator + "avScanner.properties";
		this.pathToGeneratedFile =
			Paths.get(".").toAbsolutePath().normalize().toString() + File.separator + "src" + File.separator + "test"
				+ File.separator + "resources" + File.separator + "avScanner.properties_generated";
		this.icapInputFilesFolderPath =
			Paths.get(".").toAbsolutePath().normalize().toString() + File.separator + "src" + File.separator + "test"
				+ File.separator + "resources" + File.separator + "icap-responses" + File.separator;
		this.avTemplateConfHolder = AntivirusConfigurationManager.getInstance().getScannerConfiguration(pathToTemplateFile);
	}

	public AntivirusConfigurationHolder getAvConfHolderFromTemplate()
	{
		return avTemplateConfHolder;
	}

	public String getPathToTemplateFile()
	{
		return pathToTemplateFile;
	}

	public String getPathToGeneratedFile()
	{
		return pathToGeneratedFile;
	}

	public String getIcapInputFilesFolderPath()
	{
		return icapInputFilesFolderPath;
	}

	public File makeFile(String pathToFile, String property, String propertyValue) throws IOException
	{
		File propsFile = new File(pathToFile);
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
						writer.write(avTemplateConfHolder.getHostname());
						break;
					case "port":
						writer.write(String.valueOf(avTemplateConfHolder.getPort()));
						break;
					case "service":
						writer.write(avTemplateConfHolder.getService());
						break;
					case "ICAPServerVersion":
						writer.write(avTemplateConfHolder.getICAPServerVersion());
						break;
					case "previewSize":
						writer.write(String.valueOf(avTemplateConfHolder.getPreviewSize()));
						break;
					case "stdSendLength":
						writer.write(String.valueOf(avTemplateConfHolder.getStdSendLength()));
						break;
					case "stdReceiveLength":
						writer.write(String.valueOf(avTemplateConfHolder.getStdReceiveLength()));
						break;
					case "connectionTimeout":
						writer.write(String.valueOf(avTemplateConfHolder.getConnectionTimeout()));
						break;
					case "rejectFileOnError":
						writer.write(String.valueOf(avTemplateConfHolder.isRejectFileOnError()));
						break;
					case "scanFromIntegrator":
						writer.write(String.valueOf(avTemplateConfHolder.isScanFromIntegrator()));
						break;
					case "maxFileSize":
						writer.write(String.valueOf(avTemplateConfHolder.getMaxFileSize()));
						break;
					case "fileNameRestriction":
						List<String> fileNameRestrictions = avTemplateConfHolder.getFilenameRestrictions();
						sb = new StringBuilder();
						if (!fileNameRestrictions.isEmpty())
							for (String fnRestr : fileNameRestrictions)
								sb.append(fnRestr + ",");
						if (sb.toString().length() > 0)
							writer.write(sb.toString().substring(0, sb.length() - 1));
						break;
					case "fileExtensionRestriction":
						List<String> fileExtensionRestrictions = avTemplateConfHolder.getFileExtensionRestriction();
						sb = new StringBuilder();
						if (!fileExtensionRestrictions.isEmpty())
							for (String feRestr : fileExtensionRestrictions)
								sb.append(feRestr + ",");
						if (sb.toString().length() > 0)
							writer.write(sb.toString().substring(0, sb.length() - 1));
						break;
					case "protocolRestriction":
						List<String> protocolRestrictions = avTemplateConfHolder.getProtocolRestrictions();
						sb = new StringBuilder();
						if (!protocolRestrictions.isEmpty())
							for (String prRestr : protocolRestrictions)
								sb.append(prRestr + ",");
						if (sb.toString().length() > 0)
							writer.write(sb.toString().substring(0, sb.length() - 1));
						break;
					case "partnerNameRestriction":
						List<String> partnerNameRestrictions = avTemplateConfHolder.getRestrictedPartners();
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

}
