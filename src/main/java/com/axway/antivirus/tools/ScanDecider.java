package com.axway.antivirus.tools;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.inlineprocessor.AntivirusProcessor;
import com.axway.antivirus.providers.ExchangePointProvider;
import com.axway.util.StringUtil;
import com.cyclonecommerce.api.inlineprocessing.Message;
import com.cyclonecommerce.collaboration.Party;
import com.cyclonecommerce.collaboration.partyconfiguration.PartyManagerFactory;
import com.cyclonecommerce.collaboration.transport.ExchangePoint;
import com.cyclonecommerce.collaboration.transport.ExchangePointManager;

import static com.axway.antivirus.inlineprocessor.AntivirusProcessor.AV_SCAN_STATUS;

import org.apache.log4j.Logger;

/**
 * Class that helps to decide if the file should be sent to scanning or not
 */
public class ScanDecider
{

	private static final Logger logger = Logger.getLogger(AntivirusProcessor.class.getName());
	private final ExchangePointProvider epProvider;
	private final AntivirusConfigurationHolder avHolder;

	/**
	 * @param avConfHolder The configuration holder
	 */
	public ScanDecider(AntivirusConfigurationHolder avConfHolder)
	{
		this.avHolder = avConfHolder;
		epProvider = new ExchangePointProvider()
		{
			@Override
			public ExchangePoint get(String epId)
			{
				return ExchangePointManager.getInstance().getExchangePoint(epId);
			}
		};
	}

	/**
	 * @param epProvider The exchange point provider
	 * @param avConfHolder The configuration holder
	 */
	public ScanDecider(ExchangePointProvider epProvider, AntivirusConfigurationHolder avConfHolder)
	{
		this.epProvider = epProvider;
		this.avHolder = avConfHolder;
	}

	/**
	 * Processes all restrictions from the <code>{avScannerConfFilePath}</code> file
	 * If a restriction matches the message, returns false
	 * If no restriction matches, returns true
	 *
	 * @param message The message to be validated for scanning
	 * @return a boolean showing if the message should be scanned or not
	 **/
	public Boolean isValidForScanning(Message message)
	{
		return isMessageSizeValid(message) && isFileNameValid(message) && isFileExtensionValid(message)
			&& isBusinessProtocolValid(message) && isPartnerNameValid(message);
	}

	/**
	 * Processes message size restriction from the <code>{avScannerConfFilePath}</code> file
	 * <p>If the message size is grater than the restriction, returns false
	 * else returns true</p>
	 *
	 * @param message The message to be validated for scanning
	 * @return a boolean showing if the message should be scanned or not
	 **/
	public Boolean isMessageSizeValid(Message message)
	{
		long messageLength = message.getData().length();
		if (avHolder.getMaxFileSize() > 0 && messageLength > avHolder.getMaxFileSize())
		{
			if (logger.isDebugEnabled())
				logger.debug("Message size is grater than the restriction added in configuration file. Message will not be scanned.");
			message.setMetadata(AV_SCAN_STATUS, AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
			return false;
		}
		return true;
	}

	/**
	 * Processes message file name restriction from the <code>{avScannerConfFilePath}</code> file
	 * <p>If the message file name matches the value from the configuration properties, returns false
	 * else returns true</p>
	 *
	 * @param message The message to be validated for scanning
	 * @return a boolean showing if the message should be scanned or not
	 **/
	public Boolean isFileNameValid(Message message)
	{
		String consumptionFilename = message.getMetadata("ConsumptionFilename");
		if (!avHolder.getFilenameRestrictions().isEmpty() && !StringUtil.isNullEmptyOrBlank(consumptionFilename))
			for (String fileName : avHolder.getFilenameRestrictions())
			{
				if (consumptionFilename.equalsIgnoreCase(fileName))
				{
					if (logger.isDebugEnabled())
						logger.debug("File name corresponds to the restriction added in configuration file. Message will not be scanned.");
					message.setMetadata(AV_SCAN_STATUS, AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
					return false;
				}
			}
		return true;
	}

	/**
	 * Processes message file extension restriction from the <code>{avScannerConfFilePath}</code> file
	 * <p>If the message file extension matches the file extension restriction/s from the configuration properties, returns false
	 * else returns true</p>
	 *
	 * @param message The message to be validated for scanning
	 * @return a boolean showing if the message should be scanned or not
	 **/
	public Boolean isFileExtensionValid(Message message)
	{
		String fileExtension = message.getMetadata("ConsumptionFilenameExtension");
		if (!avHolder.getFileExtensionRestriction().isEmpty() && !StringUtil.isNullEmptyOrBlank(fileExtension))
			for (String fileExt : avHolder.getFileExtensionRestriction())
			{
				if (fileExtension.replace(".", "").equalsIgnoreCase(fileExt))
				{
					if (logger.isDebugEnabled())
						logger.debug("File extension corresponds to the restriction added in configuration file. Message will not be scanned.");
					message.setMetadata(AV_SCAN_STATUS, AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
					return false;
				}
			}
		return true;
	}

	/**
	 * Processes business protocol restriction from the <code>{avScannerConfFilePath}</code> file
	 * <p>If the business protocol of the message matches business protocol restriction/s from the configuration properties, returns false
	 * else returns true</p>
	 *
	 * @param message The message to be validated for scanning
	 * @return a boolean showing if the message should be scanned or not
	 **/
	public Boolean isBusinessProtocolValid(Message message)
	{
		ExchangePoint ep = epProvider.get(message.getMetadata("ConsumptionExchangePointId"));
		if (!avHolder.getProtocolRestrictions().isEmpty() && ep != null)
		{
			String businessProtocolType = ep.getConsumptionProps().getBusinessProtocolType();
			if (!StringUtil.isNullEmptyOrBlank(businessProtocolType))
				for (String protocol : avHolder.getProtocolRestrictions())
				{
					if (businessProtocolType.equalsIgnoreCase(protocol))
					{
						if (logger.isDebugEnabled())
							logger.debug("The protocol corresponds to the restriction added in configuration file. Message will not be scanned.");
						message.setMetadata(AV_SCAN_STATUS, AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
						return false;
					}
				}
		}
		return true;
	}

	/**
	 * Processes partner name restriction from the <code>{avScannerConfFilePath}</code> file
	 * <p>If the message partner name matches partner name restriction/s from the configuration file, returns false
	 * else returns true</p>
	 *
	 * @param message The message to be validated for scanning
	 * @return a boolean showing if the message should be scanned or not
	 **/
	public Boolean isPartnerNameValid(Message message)
	{
		String partner = "";
		ExchangePoint ep = epProvider.get(message.getMetadata("ConsumptionExchangePointId"));
		if (!avHolder.getRestrictedPartners().isEmpty() && ep != null)
		{
			Party party = PartyManagerFactory.getPartyManager().getPartyById(ep.getConsumptionProps().getSender());
			if (party != null)
				partner = party.getPartyName();
			if (!StringUtil.isNullEmptyOrBlank(partner))
				for (String partnerName : avHolder.getRestrictedPartners())
				{
					if (partner.equalsIgnoreCase(partnerName))
					{
						if (logger.isDebugEnabled())
							logger.debug("The receiving party corresponds to the restriction added in configuration file. Message will not be scanned.");
						message.setMetadata(AV_SCAN_STATUS, AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
						return false;
					}
				}
		}
		return true;
	}

}
