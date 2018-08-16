package com.axway.antivirus.inlineprocessor;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.icap.AntivirusClient;
import com.axway.util.StringUtil;
import com.cyclonecommerce.api.inlineprocessing.Message;
import com.cyclonecommerce.api.inlineprocessing.MessageProcessor;
import com.cyclonecommerce.collaboration.Party;
import com.cyclonecommerce.collaboration.partyconfiguration.PartyManagerFactory;
import com.cyclonecommerce.collaboration.transport.ExchangePoint;
import com.cyclonecommerce.collaboration.transport.ExchangePointManager;
import com.cyclonecommerce.util.file.FileRegistryHelper;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

import static com.axway.antivirus.util.Constants.FS;

public class AntivirusProcessor implements MessageProcessor
{
	private static final Logger logger = Logger.getLogger(AntivirusProcessor.class.getName());
	private static final String AV_SCAN_STATUS = "AVScanStatus";

	private static String avScannerConfFilePath;

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

	static
	{
		try
		{
			avScannerConfFilePath =
				FileRegistryHelper.getInstance().getCommonDir().getCanonicalPath() + FS + "conf" + FS + "avConf" + FS
					+ "avScanner.properties";
		}
		catch (IOException ioex)
		{
			logger.error("Can't get path to shared folder: " + ioex.getMessage());
		}
	}

	@Override
	public void setParameters(String parameters)
	{
		//something here
	}

	@Override
	public void process(Message message)
	{
		//this should be the default value, if not set in properties file it will be true
		Boolean rejectFileOnError = true;
		try
		{
			//receipts have no content and should not be scanned
			if (message.getData() == null || message.getData().length() == 0)
				return;
			logger.info(
				"Inline processor AntivirusProcessor BEGIN (Thread ID = " + Thread.currentThread().getId() + ")");

			long messageLength = message.getData().length();
			logger.info("Message size: " + messageLength);
			logger.info(
				"Message sent to the AntivirusProcessor through: \"" + message.getMetadata("PickupName") + "\" pickup");

			// Create a temporary file containing the message content
			File temp = message.getData().toFile();

			//get the configuration manager instance
			AntivirusConfigurationManager avManager = AntivirusConfigurationManager.getInstance();
			//get the scanner  configuration
			AntivirusConfigurationHolder avConfHolder = avManager.getScannerConfiguration(avScannerConfFilePath);
			if (avConfHolder == null)
			{
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.ERROR.getValue());
				message.reject("Antivirus configuration file is corrupt; check logs for more details.");
				logger.error("Antivirus configuration file is corrupt; message will be rejected.");
				return;
			}
			logger.info("Antivirus configuration: " + avConfHolder.toString());
			rejectFileOnError = avConfHolder.isRejectFileOnError();

			//Get the direction metadata from the message
			//if the direction is internal the message comes from integrator
			//if the property (scanFromIntegrator) is not set to true, we should not scan the file
			String direction = message.getMetadata("Direction");
			if ("Internal".equalsIgnoreCase(direction) && !avConfHolder.isScanFromIntegrator())
			{
				logger.info("Property scanFromIntegrator is set to false, the message received from Integrator will not be scanned.");
				return;
			}

			if (!shouldScan(message, avConfHolder))
				return;

			//instantiate the ICAP client based on the scanner configuration
			AntivirusClient client = new AntivirusClient(avConfHolder.getHostname(), avConfHolder.getPort(), avConfHolder.getService(), avConfHolder.getServerVersion(), avConfHolder.getPreviewSize(), avConfHolder.getStdReceiveLength(), avConfHolder.getStdSendLength(), avConfHolder.getConnectionTimeout());

			//connect to the ICAP client and ask server for OPTIONS
			client.connect();

			//scan the file
			boolean result = client.scanFile(temp);

			//disconnect from the icap server
			client.disconnect();

			if (result)
			{
				logger.info("Message verified and accepted.");
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.CLEAN.getValue());
			}
			else
			{
				logger.error("Message Infected - rejecting message");
				message.reject("Message rejected - Infected - " + client.getFailureReason().toString());
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.INFECTED.getValue());
				temp.delete();
				return;

			}
			temp.delete();
		}
		catch (IOException ex)
		{

			logger.error("IO error occurred when scanning file " + ": " + ex.getMessage());
			if (rejectFileOnError)
			{
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.ERROR.getValue());
				message.reject("An IO error occurred when scanning the file: " + ex);
			}

		}
		catch (Exception ex)
		{

			logger.error("Other error while processing file " + ": " + ex.getMessage());
			if (rejectFileOnError)
			{
				message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.ERROR.getValue());
				message.reject("An error occurred when scanning the file: " + ex.getMessage());
			}

		}
	}

	/**
	 * Processes all restrictions from the <code>{avScannerConfFilePath}</code> file
	 * If a restriction matches the message, return false
	 * If no restriction matches, return true
	 *
	 * @return a boolean showing if the message should be scanned or not
	 **/
	private Boolean shouldScan(Message message, AntivirusConfigurationHolder avConfHolder)
	{
		long messageLength = message.getData().length();
		//message size validation
		if (messageLength > avConfHolder.getMaxFileSize() && avConfHolder.getMaxFileSize() > 0)
		{
			if (logger.isDebugEnabled())
				logger.debug("Message size is grater than the restriction added in configuration file. Message will not be scanned.");
			message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.NOTSCANNED.getValue());
			return false;
		}

		//file name validation
		String consumptionFilename = message.getMetadata("ConsumptionFilename");
		if (!StringUtil.isNullEmptyOrBlank(consumptionFilename) && !avConfHolder.getFilenameRestrictions().isEmpty())
			for (String fileName : avConfHolder.getFilenameRestrictions())
			{
				if (consumptionFilename.equalsIgnoreCase(fileName))
				{
					if (logger.isDebugEnabled())
						logger.debug("File name corresponds to the restriction added in configuration file. Message will not be scanned.");
					message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.NOTSCANNED.getValue());
					return false;
				}
			}

		//file extension validation
		String fileExtension = message.getMetadata("ConsumptionFilenameExtension");
		if (!StringUtil.isNullEmptyOrBlank(fileExtension) && !avConfHolder.getFileExtensionRestriction().isEmpty())
			for (String fileExt : avConfHolder.getFileExtensionRestriction())
			{
				if (fileExtension.replace(".", "").equalsIgnoreCase(fileExt))
				{
					if (logger.isDebugEnabled())
						logger.debug("File extension corresponds to the restriction added in configuration file. Message will not be scanned.");
					message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.NOTSCANNED.getValue());
					return false;
				}
			}

		ExchangePoint ep = ExchangePointManager.getInstance().getExchangePoint(message.getMetadata("ConsumptionExchangePointId"));
		if (ep != null)
		{
			String businessProtType = ep.getConsumptionProps().getBusinessProtocolType();
			if (!StringUtil.isNullEmptyOrBlank(businessProtType) && !avConfHolder.getProtocolRestrictions().isEmpty())
				for (String protocol : avConfHolder.getProtocolRestrictions())
				{
					if (businessProtType.equalsIgnoreCase(protocol))
					{
						if (logger.isDebugEnabled())
							logger.debug("The protocol corresponds to the restriction added in configuration file. Message will not be scanned.");
						message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.NOTSCANNED.getValue());
						return false;
					}
				}
		}
		//partner name validation
		String partner = "";
		String direction = message.getMetadata("Direction");
		if (ep != null)
			if (direction.equalsIgnoreCase("outbound"))
			{
				Party party = PartyManagerFactory.getPartyManager().getPartyById(ep.getConsumptionProps().getReceiver());
				if (party != null)
					partner = party.getPartyName();
			}
			else
			{
				Party party = PartyManagerFactory.getPartyManager().getPartyById(ep.getConsumptionProps().getSender());
				if (party != null)
					partner = party.getPartyName();
			}
		if (!StringUtil.isNullEmptyOrBlank(partner) && !avConfHolder.getRestrictedPartners().isEmpty())
			for (String partnerName : avConfHolder.getRestrictedPartners())
			{
				if (partner.equalsIgnoreCase(partnerName))
				{
					if (logger.isDebugEnabled())
						logger.debug("The receiving party corresponds to the restriction added in configuration file. Message will not be scanned.");
					message.setMetadata(AV_SCAN_STATUS, SCAN_CODES.NOTSCANNED.getValue());
					return false;
				}
			}
		return true;
	}

	public static String getAvScannerConfFilePath()
	{
		return avScannerConfFilePath;
	}
}

