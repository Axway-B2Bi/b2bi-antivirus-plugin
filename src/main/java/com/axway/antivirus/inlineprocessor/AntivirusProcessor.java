// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.inlineprocessor;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.icap.AntivirusClient;
import com.axway.antivirus.tools.ScanDecider;
import com.axway.util.StringUtil;
import com.cyclonecommerce.api.inlineprocessing.Message;
import com.cyclonecommerce.api.inlineprocessing.MessageProcessor;
import com.cyclonecommerce.collaboration.MetadataDictionary;
import com.cyclonecommerce.util.file.FileRegistryHelper;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

import static com.axway.antivirus.configuration.Constants.FS;

public class AntivirusProcessor implements MessageProcessor
{
	private static final Logger logger = Logger.getLogger(AntivirusProcessor.class);
	public static final String AV_SCAN_STATUS = "AVScanStatus";
	public static final String AV_SCAN_INFO = "AVScanInfo";

	private static String avScannerConfFilePath = null;
	private static AntivirusConfigurationManager avManager;

	private AntivirusClient client;

	public enum SCAN_CODES
	{
		CLEAN("Clean"), INFECTED("Infected"), ERROR("Error"), NOTSCANNED("NotScanned");

		private String value;

		SCAN_CODES(String value)
		{
			this.value = value;
		}

		public String getValue()
		{
			return value;
		}
	}

	/**
	 * Get the path to he antivirus scanner properties file <code>avScanner.properties</code>
	 */
	static
	{
		try
		{
			if (null == avScannerConfFilePath)
				avScannerConfFilePath =
					FileRegistryHelper.getInstance().getCommonDir().getCanonicalPath() + FS + "conf" + FS + "avConf"
						+ FS + "avScanner.properties";
		}
		catch (IOException ioex)
		{
			logger.error("Can't get path to shared folder: " + ioex.getMessage());
		}
	}

	@Override
	public void setParameters(String parameters)
	{
        //for future enhancements
	}

	@Override
	public void process(Message message)
	{
		//this should be the default value, if not set in properties file it will be true
		Boolean rejectFileOnError = true;
		try
		{
			//receipts have no content and should not be scanned
			if (message == null || message.getData() == null || message.getData().length() == 0)
				return;

			logger.info("Inline processor AntivirusProcessor BEGIN (Thread ID = " + Thread.currentThread().getId() + ")");

			if (logger.isDebugEnabled())
			{
				//print the message size in the te log
				logger.debug("Message size: " + message.getData().length());
			}

			logger.info("Message sent to the AntivirusProcessor through: \"" + message.getMetadata("PickupName") + "\" pickup");

			File temp = message.getData().toFile();

			if (null == avManager)
			{
				avManager = AntivirusConfigurationManager.getInstance();
			}

			//get the scanner  configuration
			AntivirusConfigurationHolder avConfHolder = avManager.getScannerConfiguration(avScannerConfFilePath);
			if (avConfHolder == null)
			{
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.ERROR.getValue());
				message.setMetadata(AV_SCAN_INFO, "Antivirus configuration file is corrupt; check logs for more details.");
				logger.error("Antivirus configuration file is corrupt; message will be rejected.");
				return;
			}

			if (logger.isDebugEnabled())
			{
				//print in the te log the configuration used for this message
				logger.debug("Antivirus configuration: " + avConfHolder.toString());
			}

			rejectFileOnError = avConfHolder.isRejectFileOnError();

			//Get the direction metadata from the message
			//if the direction is internal the message comes from integrator
			//if the property (scanFromIntegrator) is not set to true (in the configuration file), we should not scan the file
			if ("Internal".equalsIgnoreCase( message.getMetadata("Direction")) && !avConfHolder.isScanFromIntegrator())
			{
				logger.info("Property scanFromIntegrator is set to false, the message received from Integrator will not be scanned.");
				return;
			}

			//check all restrictions from the configuration file and decide if the file should be scanned by the antivirus
			ScanDecider scanDecider = new ScanDecider(avConfHolder);
			if (!scanDecider.isValidForScanning(message))
			{
				logger.info("The message will not be scanned due to the restrictions added in the configuration file.");
				return;
			}

			//instantiate the ICAP client based on the scanner configuration
			if (null == client)
			{
				client = new AntivirusClient(
					avConfHolder.getHostname(),
					avConfHolder.getPort(),
					avConfHolder.getService(),
					avConfHolder.getICAPServerVersion(),
					avConfHolder.getPreviewSize(),
					avConfHolder.getStdReceiveLength(),
					avConfHolder.getStdSendLength(),
					avConfHolder.getConnectionTimeout());
			}

			//connect to the ICAP client and ask server for OPTIONS
			client.connect();

			//scan the file
			boolean result = client.scanFile(temp);

			//disconnect from the icap server
			client.disconnect();

			if (result)
			{
				//the antivirus didn't find a threat, message is clean
				logger.info("Message verified and accepted.");
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.CLEAN.getValue());
			}
			else
			{
				String errorMessage;
				//if the failure reason is empty - the message was correctly sent to the icap server but the antivirus
				// didn't provide information about the file, meaning it might not be scanned
				if (StringUtil.isNullEmptyOrBlank(client.getFailureReason().toString()))
					errorMessage = "Message successfully sent to the ICAP server but not scanned by the antivirus. Check the antivirus configuration.";
				else
					errorMessage = "Message Infected - rejecting message. Threat: " + client.getFailureReason().toString();
				//the antivirus found a threat, reject the message
				//the actual reject is done in the MessageProcessorExecutor class based on the metadata from the message
				message.setMetadata(AV_SCAN_INFO, errorMessage);
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.INFECTED.getValue());
				message.setMetadata(MetadataDictionary.SHOULD_NOT_DISPLAY_VIEW_AND_DOWNLOAD_LINKS, "true");
			}

			final boolean delete = temp.delete();
			if (delete)
			{
				if (logger.isDebugEnabled())
					logger.debug("Temp file successfully deleted.");
			}
			else
			{
				logger.warn("Could not delete temp file.");
			}
		}
		catch (Exception ex)
		{

			logger.error("Other error while processing file: " + ex.getMessage());
			message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.ERROR.getValue());
			if (rejectFileOnError)
			{
				message.setMetadata(AV_SCAN_INFO, "An error occurred when scanning the file: " + ex.getMessage());
				message.setMetadata(MetadataDictionary.SHOULD_NOT_DISPLAY_VIEW_AND_DOWNLOAD_LINKS, "true");
			}

		}
	}

	/**
	 * Getter for the <code>avScanner.properties</code> file path
	 *
	 * @return The path of the configuration file
	 */
	public static String getAvScannerConfFilePath()
	{
		return avScannerConfFilePath;
	}
}

