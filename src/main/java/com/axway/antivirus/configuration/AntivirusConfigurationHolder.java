package com.axway.antivirus.configuration;

import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.util.Constants;
import com.axway.util.StringUtil;

import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class AntivirusConfigurationHolder
{
	private static Logger logger = Logger.getLogger(AntivirusConfigurationHolder.class);

	private String scannerId;
	private String hostname;
	private int port;
	private String service;
	private String serverVersion;
	private int previewSize;
	private int stdReceiveLength;
	private int stdSendLength;
	private int connectionTimeout;
	private boolean rejectFileOnError;
	private boolean scanFromIntegrator;
	private long maxFileSize;
	private List<String> fileNameRestriction;
	private List<String> fileExtensionRestriction;
	private List<String> protocolRestriction;
	private List<String> partnerNameRestriction;

	public AntivirusConfigurationHolder()
	{
		//set default values for rejectFileOnError and scanFromIntegrator
		rejectFileOnError = true;
		scanFromIntegrator = false;
		fileNameRestriction = new ArrayList<>();
		fileExtensionRestriction = new ArrayList<>();
		protocolRestriction = new ArrayList<>();
		partnerNameRestriction = new ArrayList<>();
	}

	public AntivirusConfigurationHolder(AntivirusConfigurationHolder template)
	{
		fileNameRestriction = new ArrayList<>();
		fileExtensionRestriction = new ArrayList<>();
		protocolRestriction = new ArrayList<>();
		partnerNameRestriction = new ArrayList<>();

		scannerId = template.getScannerId();
		hostname = template.getHostname();
		port = template.getPort();
		service = template.getService();
		previewSize = template.getPreviewSize();
		stdReceiveLength = template.getStdReceiveLength();
		stdSendLength = template.getStdSendLength();
		connectionTimeout = template.getConnectionTimeout();
		rejectFileOnError = template.isRejectFileOnError();
		scanFromIntegrator = template.isScanFromIntegrator();
		serverVersion = template.getServerVersion();
		maxFileSize = template.getMaxFileSize();
		fileNameRestriction.addAll(template.getFilenameRestrictions());
		protocolRestriction.addAll(template.getProtocolRestrictions());
		partnerNameRestriction.addAll(template.getRestrictedPartners());
	}

	/**
	 * Universal setter method for this bean.
	 *
	 * @param prop the member to set. Allowed values are:
	 * <ul>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_HOSTNAME}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_PORT}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_SERVICE}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_ICAP_SERVER_VERSION}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_PREVIEW_SIZE}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_STANDARD_RECEIVE_LENGTH}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_STANDARD_SEND_LENGTH}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_SCAN_FROM_INTEGRATOR}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_MAX_FILE_SIZE}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_FILENAME_RESTRICTION}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_FILE_EXTENSION_RESTRICTION}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_PROTOCOL_RESTRICTION}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_PARTNER_NAME_RESTRICTION}</li>
	 * </ul>
	 * @param value the value of the property
	 */
	public void addProperty(String prop, String value) throws AntivirusException
	{
		switch (prop)
		{
			case Constants.SCANNER_CONFIGURATION_PROPERTY_HOSTNAME:
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 250)
				{
					logger.error("Antivirus hostname is invalid: \"" + value + "\"");
					throw new AntivirusException("Antivirus hostname is invalid");
				}
				else
				{
					this.setHostname(value);
					if (logger.isDebugEnabled())
						logger.debug("Antivirus hostname is: " + value);
				}

				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PORT:
				try
				{
					int portValue = Integer.parseInt(value);
					if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 5 || portValue < 0)
					{
						logger.error("Antivirus port is invalid: \"" + value + "\"");
						throw new AntivirusException("Antivirus port is invalid");
					}
					else
					{
						this.setPort(portValue);
						if (logger.isDebugEnabled())
							logger.debug("Antivirus port is: " + value);
					}
				}
				catch (NumberFormatException nfe)
				{
					logger.error("Antivirus port value is invalid: " + value);
					throw new AntivirusException("Antivirus port is invalid.");
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_SERVICE:
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 250)
				{
					logger.error("Antivirus service name is invalid: \"" + value + "\"");
					throw new AntivirusException("Antivirus service name is invalid");
				}
				else
				{
					this.setService(value);
					if (logger.isDebugEnabled())
						logger.debug("Antivirus service name is: " + value);
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_ICAP_SERVER_VERSION:
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 50)
				{
					logger.error("The ICAP server version value is invalid: \"" + value + "\"");
					throw new AntivirusException("Antivirus server version value is invalid");
				}
				else
				{
					this.setServerVersion(value);
					if (logger.isDebugEnabled())
						logger.debug("The ICAP server version is: " + value);
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PREVIEW_SIZE:
				String error = "Antivirus preview size value is invalid: \"" + value
					+ "\", preview size from server will be used.";
				try
				{
					if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 15)
					{
						logger.error(error);
						this.setPreviewSize(-1);
						return;
					}
					int size = Integer.parseInt(value);
					if (size <= 0)
					{
						logger.error(error);
						this.setPreviewSize(-1);
					}
					else
					{
						this.setPreviewSize(size);
						if (logger.isDebugEnabled())
							logger.debug("Antivirus preview size is: " + value);
					}
				}
				catch (NumberFormatException nfe)
				{
					logger.error(error);
					this.setPreviewSize(-1);
					return;
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_STANDARD_RECEIVE_LENGTH:
				try
				{
					if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 15)
					{
						logger.error("Antivirus standard receive length value is invalid: \"" + value
							+ "\", standard receive length default value  will be used.");
						this.setStdReceiveLength(8192);
						return;
					}
					int receiveLength = Integer.parseInt(value);
					if (receiveLength <= 0)
					{
						logger.error("Antivirus standard receive length value is invalid: \"" + value
							+ "\", standard receive length default value  will be used.");
						this.setStdReceiveLength(8192);
					}
					else
					{
						this.setStdReceiveLength(receiveLength);
						if (logger.isDebugEnabled())
							logger.debug("Antivirus standard receive length is: " + value);
					}
				}
				catch (NumberFormatException nfe)
				{
					logger.error("Antivirus standard receive length is invalid, standard receive length default value  will be used.");
					this.setStdReceiveLength(8192);
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_STANDARD_SEND_LENGTH:
				try
				{
					if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 15)
					{
						logger.error("Antivirus standard send length value is invalid: \"" + value
							+ "\", standard send length default will be used.");
						this.setStdSendLength(8192);
						return;
					}
					int sendLength = Integer.parseInt(value);
					if (sendLength <= 0)
					{
						logger.error("Antivirus standard send length value is invalid: \"" + value
							+ "\", standard send length default will be used.");
						this.setStdSendLength(8192);
					}
					else
					{
						this.setStdSendLength(sendLength);
						if (logger.isDebugEnabled())
							logger.debug("Antivirus standard send length is: " + value);
					}

				}
				catch (NumberFormatException nfe)
				{
					logger.error("Antivirus standard send length value is invalid, standard send length default will be used.");
					this.setStdSendLength(8192);
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT:
				try
				{
					if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 15)
					{
						logger.error("Connection timeout value is invalid, default value will be set.");
						this.setConnectionTimeout(10000);
						return;
					}
					int timeout = Integer.parseInt(value);
					if (timeout <= 0)
					{
						logger.error(
							"Connection timeout value is invalid: " + timeout + ". Default value will be set.");
						this.setConnectionTimeout(10000);
					}
					else
					{
						this.setConnectionTimeout(timeout);
						if (logger.isDebugEnabled())
							logger.debug("Antivirus connection timeout is: " + value);

					}
				}
				catch (NumberFormatException nfe)
				{
					logger.error("Connection timeout value is invalid, default value will be set.");
					this.setConnectionTimeout(10000);
					return;
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR:
				if (!StringUtil.isNullEmptyOrBlank(value))
					switch (value)
					{
						case "true":
						case "false":
							this.setRejectFileOnError(Boolean.valueOf(value));
							if (logger.isDebugEnabled())
								logger.debug("Reject file on error value is: " + value);
							break;
						default:
							this.setRejectFileOnError(Boolean.valueOf("true"));
							logger.error("Incorrect value for reject file on error property. Default value will be used: \"true\".");
							break;
					}
				else
				{
					this.setRejectFileOnError(Boolean.valueOf("true"));
					logger.error("Incorrect value for reject file on error property. Default value will be used: \"true\".");
				}

				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_SCAN_FROM_INTEGRATOR:
				if (!StringUtil.isNullEmptyOrBlank(value))
					switch (value)
					{
						case "true":
						case "false":
							this.setScanFromIntegrator(Boolean.valueOf(value));
							if (logger.isDebugEnabled())
								logger.debug("Scan from integrator value is: " + value);
							break;
						default:
							this.setScanFromIntegrator(false);
							logger.error("Incorrect value for scan from integrator property. Default value will be used: \"false\".");
							break;
					}
				else
				{
					this.setScanFromIntegrator(false);
					logger.error("Incorrect value for scan from integrator property. Default value will be used: \"false\".");
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_MAX_FILE_SIZE:
				try
				{
					if (StringUtil.isNullEmptyOrBlank(value))
					{
						this.setMaxFileSize(-1);
						return;
					}
					long maxSize = Long.parseLong(value);
					if (value.length() > 15 || maxSize <= 0)
					{
						logger.error("Incorrect max file size value. The restriction will not be used.");
						this.setMaxFileSize(-1);
					}
					else
					{
						this.setMaxFileSize(maxSize);
						if (logger.isDebugEnabled())
							logger.debug("Antivirus maximum file size is: " + value);
					}
				}
				catch (NumberFormatException nfe)
				{
					logger.error("Incorrect max file size value. The restriction will not be used.");
					this.setMaxFileSize(-1);
				}
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_FILENAME_RESTRICTION:
				List<String> filenamePatterns = new ArrayList<>();
				if (!StringUtil.isNullEmptyOrBlank(value))
				{
					String[] splitValues = value.split(",");
					for (String filenamePattern : splitValues)
					{
						if (!StringUtil.isNullEmptyOrBlank(filenamePattern))
						{
							filenamePatterns.add(filenamePattern);
							if (logger.isDebugEnabled())
								logger.debug("File name restriction added: " + filenamePattern);
						}
					}
				}
				this.setFilenameRestrictions(filenamePatterns);
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_FILE_EXTENSION_RESTRICTION:
				List<String> fileExtRestrictions = new ArrayList<>();
				if (!StringUtil.isNullEmptyOrBlank(value))
				{
					String[] splitValues = value.split(",");
					for (String fileExtRestriction : splitValues)
					{
						if (!StringUtil.isNullEmptyOrBlank(fileExtRestriction))
						{
							fileExtRestrictions.add(fileExtRestriction);
							if (logger.isDebugEnabled())
								logger.debug("File extension restriction added: " + fileExtRestriction);
						}
					}
				}
				this.setFileExtensionRestriction(fileExtRestrictions);
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PROTOCOL_RESTRICTION:
				List<String> protocolRestrictions = new ArrayList<>();
				if (!StringUtil.isNullEmptyOrBlank(value))
				{
					String[] splitValues = value.split(",");
					for (String protocol : splitValues)
					{
						if (!StringUtil.isNullEmptyOrBlank(protocol))
						{
							protocolRestrictions.add(protocol);
							if (logger.isDebugEnabled())
								logger.debug("Protocol restriction added: " + protocol);
						}
					}
				}
				this.setProtocolRestrictions(protocolRestrictions);
				break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PARTNER_NAME_RESTRICTION:
				List<String> partnerNameRestrictions = new ArrayList<>();
				if (!StringUtil.isNullEmptyOrBlank(value))
				{
					String[] splitValues = value.split(",");
					for (String partner : splitValues)
					{
						if (!StringUtil.isNullEmptyOrBlank(partner))
						{
							partnerNameRestrictions.add(partner);
							if (logger.isDebugEnabled())
								logger.debug("Partner name restriction added: " + partner);
						}
					}
				}
				this.setPartnerRestrictions(partnerNameRestrictions);
				break;
			default:
				logger.debug("Unknown property: " + prop);
		}
	}

	public String getScannerId()
	{
		return scannerId;
	}

	public void setScannerId(String id)
	{
		this.scannerId = id;
	}

	public String getHostname()
	{
		return hostname;
	}

	public void setHostname(String hostname)
	{
		this.hostname = hostname;
	}

	public int getPort()
	{
		return port;
	}

	public void setPort(int port)
	{
		this.port = port;
	}

	public String getService()
	{
		return service;
	}

	public void setService(String mService)
	{
		this.service = mService;
	}

	public int getConnectionTimeout()
	{
		return connectionTimeout;
	}

	public void setConnectionTimeout(int mConnectionTimeout)
	{
		this.connectionTimeout = mConnectionTimeout;
	}

	public boolean isRejectFileOnError()
	{
		return rejectFileOnError;
	}

	public void setRejectFileOnError(boolean mRejectFileOnError)
	{
		this.rejectFileOnError = mRejectFileOnError;
	}

	public int getPreviewSize()
	{
		return previewSize;
	}

	public void setPreviewSize(int mPreviewSize)
	{
		this.previewSize = mPreviewSize;
	}

	public int getStdReceiveLength()
	{
		return stdReceiveLength;
	}

	public void setStdReceiveLength(int stdReceiveLength)
	{
		this.stdReceiveLength = stdReceiveLength;
	}

	public int getStdSendLength()
	{
		return stdSendLength;
	}

	public void setStdSendLength(int stdSendLength)
	{
		this.stdSendLength = stdSendLength;
	}

	public long getMaxFileSize()
	{
		return maxFileSize;
	}

	public void setMaxFileSize(long filesizeRestriction)
	{
		this.maxFileSize = filesizeRestriction;
	}

	public List<String> getFilenameRestrictions()
	{
		return fileNameRestriction;
	}

	public void setFilenameRestrictions(List<String> restrictedFilenamePatterns)
	{
		this.fileNameRestriction = restrictedFilenamePatterns;
	}

	public List<String> getProtocolRestrictions()
	{
		return protocolRestriction;
	}

	public void setProtocolRestrictions(List<String> restrictedProtocols)
	{
		this.protocolRestriction = restrictedProtocols;
	}

	public List<String> getRestrictedPartners()
	{
		return partnerNameRestriction;
	}

	public void setPartnerRestrictions(List<String> restrictedPartners)
	{
		this.partnerNameRestriction = restrictedPartners;
	}

	public List<String> getFileExtensionRestriction()
	{
		return fileExtensionRestriction;
	}

	public void setFileExtensionRestriction(List<String> fileExtensionRestriction)
	{
		this.fileExtensionRestriction = fileExtensionRestriction;
	}

	public String getServerVersion()
	{
		return serverVersion;
	}

	public void setServerVersion(String mVersion)
	{
		this.serverVersion = mVersion;
	}

	public boolean isScanFromIntegrator()
	{
		return scanFromIntegrator;
	}

	public void setScanFromIntegrator(boolean scanFromIntegrator)
	{
		this.scanFromIntegrator = scanFromIntegrator;
	}

	@Override
	public String toString()
	{
		return "AntivirusConfigurationHolder{" + "scannerId='" + scannerId + '\'' + ", hostname='" + hostname + '\''
			+ ", port=" + port + ", service='" + service + '\'' + ", serverVersion='" + serverVersion + '\''
			+ ", previewSize=" + previewSize + ", stdReceiveLength=" + stdReceiveLength + ", stdSendLength="
			+ stdSendLength + ", connectionTimeout=" + connectionTimeout + ", rejectFileOnError=" + rejectFileOnError
			+ ", scanFromIntegrator=" + scanFromIntegrator + ", maxFileSize=" + maxFileSize + ", fileNameRestriction="
			+ fileNameRestriction + ", fileExtensionRestriction=" + fileExtensionRestriction + ", protocolRestriction="
			+ protocolRestriction + ", partnerNameRestriction=" + partnerNameRestriction + '}';
	}
}