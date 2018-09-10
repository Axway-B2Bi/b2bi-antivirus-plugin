package com.axway.antivirus.configuration;

import com.axway.antivirus.configuration.validators.ValidateBoolean;
import com.axway.antivirus.configuration.validators.ValidateRangedInteger;
import com.axway.antivirus.configuration.validators.ValidateRangedLong;
import com.axway.antivirus.configuration.validators.ValidateRangedString;
import com.axway.antivirus.configuration.validators.ValidationStrategy;

/**
 * All the properties from the <code>avScanner.properties</code> file with their default values and their validation strategies
 */
public enum PropertyKey
{

	HOSTNAME(Constants.SCANNER_CONFIGURATION_PROPERTY_HOSTNAME, new ValidateRangedString(250)),
	PORT(Constants.SCANNER_CONFIGURATION_PROPERTY_PORT, new ValidateRangedInteger(0, 99999)),
	SERVICE(Constants.SCANNER_CONFIGURATION_PROPERTY_SERVICE, new ValidateRangedString(250)),
	ICAP_SERVER_VERSION(Constants.SCANNER_CONFIGURATION_PROPERTY_ICAP_SERVER_VERSION, new ValidateRangedString(25)),
	PREVIEW_SIZE(Constants.SCANNER_CONFIGURATION_PROPERTY_PREVIEW_SIZE, new ValidateRangedInteger(0,Integer.MAX_VALUE),"1024"),
	STANDARD_RECEIVE_LENGTH(Constants.SCANNER_CONFIGURATION_PROPERTY_STANDARD_RECEIVE_LENGTH, new ValidateRangedInteger(0,Integer.MAX_VALUE),"8192"),
	STANDARD_SEND_LENGTH(Constants.SCANNER_CONFIGURATION_PROPERTY_STANDARD_SEND_LENGTH, new ValidateRangedInteger(0,Integer.MAX_VALUE),"8192"),
	CONNECTION_TIMEOUT(Constants.SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT, new ValidateRangedInteger(0,Integer.MAX_VALUE),"10000"),
	REJECT_FILE_ON_ERROR(Constants.SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR, new ValidateBoolean(),"true"),
	SCAN_FROM_INTEGRATOR(Constants.SCANNER_CONFIGURATION_PROPERTY_SCAN_FROM_INTEGRATOR, new ValidateBoolean(),"false"),
	MAX_FILE_SIZE(Constants.SCANNER_CONFIGURATION_PROPERTY_MAX_FILE_SIZE, new ValidateRangedLong(0,Long.MAX_VALUE),"-1"),
	FILENAME_RESTRICTION(Constants.SCANNER_CONFIGURATION_PROPERTY_FILENAME_RESTRICTION),
	PROTOCOL_RESTRICTION(Constants.SCANNER_CONFIGURATION_PROPERTY_PROTOCOL_RESTRICTION),
	FILE_EXTENSION_RESTRICTION(Constants.SCANNER_CONFIGURATION_PROPERTY_FILE_EXTENSION_RESTRICTION),
	PARTNER_NAME_RESTRICTION(Constants.SCANNER_CONFIGURATION_PROPERTY_PARTNER_NAME_RESTRICTION);

	private final String propertyName;
	private ValidationStrategy validationStrategy;
	private String defaultValue;

	PropertyKey(String name)
	{
		this.propertyName = name;
	}

	PropertyKey(String name, ValidationStrategy validationStrategy)
	{
		this.propertyName = name;
		this.validationStrategy = validationStrategy;
	}

	PropertyKey(String name, ValidationStrategy validationStrategy, String defaultValue)
	{
		this.propertyName = name;
		this.validationStrategy = validationStrategy;
		this.defaultValue = defaultValue;
	}

	public String getPropertyName()
	{
		return propertyName;
	}

	public ValidationStrategy getValidationStrategy()
	{
		return validationStrategy;
	}

	public String getDefaultValue()
	{
		return defaultValue;
	}
}
