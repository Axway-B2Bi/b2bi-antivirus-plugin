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
	private int connectionTimeout;
	private boolean rejectFileOnError;
	private long maxFileSize;
	private List<String> fileNameRestriction;
	private List<String> fileExtensionRestriction;
	private List<String> protocolRestriction;
	private List<String> partnerNameRestriction;

	public AntivirusConfigurationHolder()
	{
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
		connectionTimeout = template.getConnectionTimeout();
		rejectFileOnError = template.isRejectFileOnError();
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
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT}</li>
	 * <li>{@link Constants#SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR}</li>
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
			{
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
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PORT:
			{
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 10)
				{
					logger.error("Antivirus port is invalid: \"" + value + "\"");
					throw new AntivirusException("Antivirus port is invalid");
				}
				else
				{
					try
					{
						this.setPort(Integer.parseInt(value));
						if (logger.isDebugEnabled())
							logger.debug("Antivirus port is: " + value);
					}
					catch (NumberFormatException nfe)
					{
						logger.error("Antivirus port value is invalid: " + value);
						throw new AntivirusException("Antivirus port is invalid.");
					}

				}
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_SERVICE:
			{
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
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_ICAP_SERVER_VERSION:
			{
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
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PREVIEW_SIZE:
			{
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 25)
				{
					logger.error("Antivirus preview size value is invalid: \"" + value + "\", preview size from server will be used.");
				}
				else
				{
					try
					{
						this.setPreviewSize(Integer.valueOf(value));
						if (logger.isDebugEnabled())
							logger.debug("Antivirus preview size is: " + value);
					}
					catch (NumberFormatException nfe)
					{
						logger.error("Antivirus preview size  value is invalid: " + value);
						throw new AntivirusException("Antivirus preview size value is invalid.");
					}
				}
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT:
			{
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 25)
				{
					logger.error("Antivirus connection timeout value is invalid: \"" + value + "\"");
					throw new AntivirusException("Antivirus connection timeout value is invalid.");
				}
				else
				{
					try
					{
						this.setConnectionTimeout(Integer.valueOf(value));
						if (logger.isDebugEnabled())
							logger.debug("Antivirus connection timeout is: " + value);
					}
					catch (NumberFormatException nfe)
					{
						logger.error("Antivirus connection timeout value is invalid: " + value);
						throw new AntivirusException("Antivirus connection timeout value is invalid.");
					}
				}
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR:
			{
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 10)
					this.setRejectFileOnError(Boolean.valueOf("true"));
				else
				{
					this.setRejectFileOnError(Boolean.valueOf(value));
					if (logger.isDebugEnabled())
						logger.debug("Reject file on error value is: " + value);
				}
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_MAX_FILE_SIZE:
			{
				if (StringUtil.isNullEmptyOrBlank(value) || value.length() > 25)
				{
					this.setMaxFileSize(-1);
					return;
				}
				else
				{
					try
					{
						this.setMaxFileSize(Long.parseLong(value));
						if (logger.isDebugEnabled())
							logger.debug("Antivirus maximum file size is: " + value);
					}
					catch (NumberFormatException nfe)
					{
						logger.error("Antivirus maximum file size value is invalid: " + value);
						throw new AntivirusException("Antivirus maximum file size value is invalid.");
					}
				}
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_FILENAME_RESTRICTION:
			{
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
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_FILE_EXTENSION_RESTRICTION:
			{
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
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PROTOCOL_RESTRICTION:
			{
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
			}
			break;
			case Constants.SCANNER_CONFIGURATION_PROPERTY_PARTNER_NAME_RESTRICTION:
			{
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
			}
			break;
			default:
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

	@Override
	public String toString()
	{
		return "AntivirusConfigurationHolder{" + "scannerId='" + scannerId + '\'' + ", hostname='" + hostname + '\''
			+ ", port=" + port + ", service='" + service + '\'' + ", serverVersion='" + serverVersion + '\''
			+ ", previewSize=" + previewSize + ", connectionTimeout=" + connectionTimeout + ", rejectFileOnError="
			+ rejectFileOnError + ", maxFileSize=" + maxFileSize + ", fileNameRestriction=" + fileNameRestriction
			+ ", fileExtensionRestriction=" + fileExtensionRestriction + ", protocolRestriction=" + protocolRestriction
			+ ", partnerNameRestriction=" + partnerNameRestriction + '}';
	}
}