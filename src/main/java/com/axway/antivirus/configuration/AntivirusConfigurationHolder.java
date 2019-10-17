// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.configuration;

import com.axway.util.StringUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * The holder for the properties found in <code>avScanner.properties</code> file
 */
public class AntivirusConfigurationHolder
{
	private String scannerId;
	private String hostname;
	private int port;
	private String service;
	private String ICAPServerVersion;
	private int previewSize;
	private int stdReceiveLength;
	private int stdSendLength;
	private int connectionTimeout;
	private boolean rejectFileOnError;
	private boolean scanFromIntegrator;
	private long maxFileSize;
	private boolean rejectFileOverMaxSize;
	private List<String> fileNameRestriction;
	private List<String> fileExtensionRestriction;
	private List<String> protocolRestriction;
	private List<String> partnerNameRestriction;

	/**
	 * Default constructor
	 */
	public AntivirusConfigurationHolder()
	{
		//set default values
		setPreviewSize(Integer.getInteger(PropertyKey.PREVIEW_SIZE.getDefaultValue()));
		setStdSendLength(Integer.getInteger(PropertyKey.STANDARD_SEND_LENGTH.getDefaultValue()));
		setStdReceiveLength(Integer.getInteger(PropertyKey.STANDARD_RECEIVE_LENGTH.getDefaultValue()));
		setConnectionTimeout(Integer.getInteger(PropertyKey.CONNECTION_TIMEOUT.getDefaultValue()));
		setRejectFileOnError(Boolean.getBoolean(PropertyKey.REJECT_FILE_ON_ERROR.getDefaultValue()));
		setScanFromIntegrator(Boolean.getBoolean(PropertyKey.SCAN_FROM_INTEGRATOR.getDefaultValue()));
		setMaxFileSize(Integer.getInteger(PropertyKey.MAX_FILE_SIZE.getDefaultValue()));
		setRejectFileOverMaxSize(Boolean.getBoolean(PropertyKey.REJECT_OVER_MAX_FILE_SIZE.getDefaultValue()));
		setFilenameRestrictions(new ArrayList<String>());
		setFileExtensionRestriction(new ArrayList<String>());
		setProtocolRestrictions(new ArrayList<String>());
		setPartnerRestrictions(new ArrayList<String>());
	}

	/**
	 * @param id The ID of the scanner
	 * @param properties Properties of the scanner corresponding to the ID
	 */
	public AntivirusConfigurationHolder(String id, Properties properties)
	{
		setScannerId(id);
		setHostname(properties.getProperty(Constants.SCANNER_CONFIGURATION_PROPERTY_HOSTNAME));
		setPort(Integer.parseInt(properties.getProperty(Constants.SCANNER_CONFIGURATION_PROPERTY_PORT)));
		setService(properties.getProperty(Constants.SCANNER_CONFIGURATION_PROPERTY_SERVICE));
		setICAPServerVersion(properties.getProperty(Constants.SCANNER_CONFIGURATION_PROPERTY_ICAP_SERVER_VERSION));

		setPreviewSize(Integer.parseInt(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_PREVIEW_SIZE)));
		setStdReceiveLength(Integer.parseInt(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_STANDARD_RECEIVE_LENGTH)));
		setStdSendLength(Integer.parseInt(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_STANDARD_SEND_LENGTH)));
		setConnectionTimeout(Integer.parseInt(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT)));
		setRejectFileOnError(Boolean.parseBoolean(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR)));
		setScanFromIntegrator(Boolean.parseBoolean(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_SCAN_FROM_INTEGRATOR)));
		setMaxFileSize(Long.parseLong(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_MAX_FILE_SIZE)));
		setRejectFileOverMaxSize(Boolean.parseBoolean((getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_REJECT_OVER_MAX_FILE_SIZE))));

		setFilenameRestrictions(getRestrictionListOfValues(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_FILENAME_RESTRICTION)));
		setFileExtensionRestriction(getRestrictionListOfValues(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_FILE_EXTENSION_RESTRICTION)));
		setProtocolRestrictions(getRestrictionListOfValues(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_PROTOCOL_RESTRICTION)));
		setPartnerRestrictions(getRestrictionListOfValues(getPropertyOrDefaultValue(properties, Constants.SCANNER_CONFIGURATION_PROPERTY_PARTNER_NAME_RESTRICTION)));
	}

	/**
	 * Returns the value associated with the propertyName from the properties
	 * If the property doesn't exist in properties, it checks for default values in PropertyKey enum
	 * If it doesn't have a default value it will return null
	 *
	 * @param properties
	 * @param propertyName
	 * @return the value for the propertyName or a default value associated or null if none are found
	 */
	private String getPropertyOrDefaultValue(Properties properties, String propertyName)
	{
		if (!StringUtil.isNullEmptyOrBlank(properties.getProperty(propertyName)))
			return properties.getProperty(propertyName);
		else
		{
			for (PropertyKey key : PropertyKey.values())
				if (key.getPropertyName().equalsIgnoreCase(propertyName) && key.getDefaultValue() != null)
					return key.getDefaultValue();
		}
		return null;
	}

	/**
	 * Returns a List of values extracted from a String
	 *
	 * @param listOfValues The String containing the list of values comma separated
	 * @return The list of values
	 */

	private List<String> getRestrictionListOfValues(String listOfValues)
	{
		List<String> values = new ArrayList<>();
		if (!StringUtil.isNullEmptyOrBlank(listOfValues))
		{
			String[] splitValues = listOfValues.split(",");
			for (String value : splitValues)
			{
				if (!StringUtil.isNullEmptyOrBlank(value))
				{
					values.add(value);
				}
			}
		}
		return values;
	}

	/**
	 * Getter for the scanner id
	 *
	 * @return The scanner id value
	 */
	public String getScannerId()
	{
		return scannerId;
	}

	/**
	 * Setter for the scanner id
	 *
	 * @param id The id for the scanner
	 */
	public void setScannerId(String id)
	{
		this.scannerId = id;
	}

	/**
	 * Getter for the hostname
	 *
	 * @return The hostname value
	 */
	public String getHostname()
	{
		return hostname;
	}

	/**
	 * Setter for the hostname
	 *
	 * @param hostname The hostname for the scanner
	 */
	public void setHostname(String hostname)
	{
		this.hostname = hostname;
	}

	/**
	 * Getter for the port
	 *
	 * @return The port value
	 */
	public int getPort()
	{
		return port;
	}

	/**
	 * Setter for the port
	 *
	 * @param port The port for the scanner
	 */
	public void setPort(int port)
	{
		this.port = port;
	}

	/**
	 * Getter for the service name
	 *
	 * @return The service name
	 */
	public String getService()
	{
		return service;
	}

	/**
	 * Setter for the service name
	 *
	 * @param service The service name for the scanner
	 */
	public void setService(String service)
	{
		this.service = service;
	}

	/**
	 * Getter for the connection timeout
	 *
	 * @return The connection timeout value
	 */
	public int getConnectionTimeout()
	{
		return connectionTimeout;
	}

	/**
	 * Setter for the connection timeout
	 *
	 * @param connectionTimeout The connection timeout value for the scanner
	 */
	public void setConnectionTimeout(int connectionTimeout)
	{
		this.connectionTimeout = connectionTimeout;
	}

	/**
	 * Getter for the reject file on error flag
	 *
	 * @return the reject file on error value
	 */
	public boolean isRejectFileOnError()
	{
		return rejectFileOnError;
	}

	/**
	 * Setter for the reject file on error flag
	 *
	 * @param rejectFileOnError The reject file on error value for the scanner
	 */
	public void setRejectFileOnError(boolean rejectFileOnError)
	{
		this.rejectFileOnError = rejectFileOnError;
	}

	/**
	 * Getter for the preview size value
	 *
	 * @return The preview size value
	 */
	public int getPreviewSize()
	{
		return previewSize;
	}

	/**
	 * Setter for the preview size
	 *
	 * @param previewSize The preview size value for the scanner
	 */
	public void setPreviewSize(int previewSize)
	{
		this.previewSize = previewSize;
	}

	/**
	 * Getter for the standard receive length value
	 *
	 * @return The standard receive length value
	 */
	public int getStdReceiveLength()
	{
		return stdReceiveLength;
	}

	/**
	 * Setter for the standard receive length value
	 *
	 * @param stdReceiveLength The standard receive length value for the scanner
	 */
	public void setStdReceiveLength(int stdReceiveLength)
	{
		this.stdReceiveLength = stdReceiveLength;
	}

	/**
	 * Getter for the standard send length value
	 *
	 * @return The standard send length value for the scanner
	 */
	public int getStdSendLength()
	{
		return stdSendLength;
	}

	/**
	 * Setter for the standard send length value
	 *
	 * @param stdSendLength The standard send length value for the scanner
	 */
	public void setStdSendLength(int stdSendLength)
	{
		this.stdSendLength = stdSendLength;
	}

	/**
	 * Getter for the max file size value
	 *
	 * @return The max file size value
	 */
	public long getMaxFileSize()
	{
		return maxFileSize;
	}

	/**
	 * Setter for the max file size value
	 *
	 * @param maxFileSize The max file size value for the scanner
	 */
	public void setMaxFileSize(long maxFileSize)
	{
		this.maxFileSize = maxFileSize;
	}

	/**
	 * Getter for the list of file name restriction value/s
	 *
	 * @return The list of file name restriction value/s for the scanner
	 */
	public List<String> getFilenameRestrictions()
	{
		return fileNameRestriction;
	}

	/**
	 * Setter for the file name restriction value/s
	 *
	 * @param restrictedFilenamePatterns The List of file name restriction value/s for the scanner
	 */
	public void setFilenameRestrictions(List<String> restrictedFilenamePatterns)
	{
		this.fileNameRestriction = restrictedFilenamePatterns;
	}

	/**
	 * Getter for the list of protocol restriction value/s
	 *
	 * @return The list of  protocol restriction value/s for the scanner
	 */
	public List<String> getProtocolRestrictions()
	{
		return protocolRestriction;
	}

	/**
	 * Setter for the list of protocol restriction value/s
	 *
	 * @param restrictedProtocols The list of protocol restriction value/s for the scanner
	 */
	public void setProtocolRestrictions(List<String> restrictedProtocols)
	{
		this.protocolRestriction = restrictedProtocols;
	}

	/**
	 * Getter for the list of partner name restriction value/s
	 *
	 * @return The list of file partner name restriction value/s for the scanner
	 */
	public List<String> getRestrictedPartners()
	{
		return partnerNameRestriction;
	}

	/**
	 * Setter for the list of partner name restriction value/s
	 *
	 * @param restrictedPartners The list of partner name restriction value/s for the scanner
	 */
	public void setPartnerRestrictions(List<String> restrictedPartners)
	{
		this.partnerNameRestriction = restrictedPartners;
	}

	/**
	 * Getter for the list of file extension restriction value/s
	 *
	 * @return The file extension restriction value/s for the scanner
	 */
	public List<String> getFileExtensionRestriction()
	{
		return fileExtensionRestriction;
	}

	/**
	 * Setter for the list of file extension restriction vaalue/s
	 *
	 * @param fileExtensionRestriction The list of file extension restriction value/s for the scanner
	 */
	public void setFileExtensionRestriction(List<String> fileExtensionRestriction)
	{
		this.fileExtensionRestriction = fileExtensionRestriction;
	}

	/**
	 * Getter for the ICAP server version
	 *
	 * @return the ICAP server version
	 */
	public String getICAPServerVersion()
	{
		return ICAPServerVersion;
	}

	/**
	 * Setter for the ICAP server version
	 *
	 * @param version The ICAP server version for the scanner
	 */
	public void setICAPServerVersion(String version)
	{
		this.ICAPServerVersion = version;
	}

	/**
	 * Getter for the reject file over max size
	 *
	 * @return the reject file over max size
	 */
	public boolean isRejectFileOverMaxSize()
	{
		return rejectFileOverMaxSize;
	}

	/**
	 * Setter for the reject file over max size
	 *
	 * @param rejectFileOverMaxSize flag to reject files over max size
	 */
	public void setRejectFileOverMaxSize(boolean rejectFileOverMaxSize)
	{
		this.rejectFileOverMaxSize = rejectFileOverMaxSize;
	}

	/**
	 * Getter for the scan from integrator value
	 *
	 * @return The scan from integrator value
	 */
	public boolean isScanFromIntegrator()
	{
		return scanFromIntegrator;
	}

	/**
	 * Setter for the scan from integrator value
	 *
	 * @param scanFromIntegrator The scan from integrator value for the scanner
	 */
	public void setScanFromIntegrator(boolean scanFromIntegrator)
	{
		this.scanFromIntegrator = scanFromIntegrator;
	}

	/**
	 * @return All the values from the <code>AntivirusConfigurationHolder</code>
	 */
	@Override
	public String toString()
	{
		return "AntivirusConfigurationHolder {"
			+ "scannerId=" + scannerId
			+ ", hostname=" + hostname
			+ ", port=" + port
			+ ", service=" + service
			+ ", ICAPServerVersion=" + ICAPServerVersion
			+ ", connectionTimeout=" + connectionTimeout
			+ ", previewSize=" + previewSize
			+ ", stdReceiveLength=" + stdReceiveLength
			+ ", stdSendLength=" + stdSendLength
			+ ", rejectFileOnError="+ rejectFileOnError
			+ ", scanFromIntegrator=" + scanFromIntegrator
			+ ", maxFileSize=" + maxFileSize
			+ ", rejectFileOverMaxSize=" + rejectFileOverMaxSize
			+ ", fileNameRestriction=" + fileNameRestriction
			+ ", fileExtensionRestriction=" + fileExtensionRestriction
			+ ", protocolRestriction=" + protocolRestriction
			+ ", partnerNameRestriction=" + partnerNameRestriction
			+ '}';
	}
}