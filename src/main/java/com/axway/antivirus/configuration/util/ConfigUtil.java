package com.axway.antivirus.configuration.util;

import com.axway.antivirus.configuration.PropertyKey;
import com.axway.antivirus.inlineprocessor.AntivirusProcessor;
import com.axway.util.StringUtil;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public class ConfigUtil
{
	private static final Logger logger = Logger.getLogger(ConfigUtil.class);
	private Properties properties;

	/**
	 * Instantiates the ConfigUtil object and gets all properties from the configuration file
	 *
	 * @param pathToFile The path to the configuration file
	 */
	public ConfigUtil(final String pathToFile)
	{
		properties = getPropertiesFromFile(pathToFile);
	}

	/**
	 * Parses the properties file and gets the unique ids
	 *
	 * @return Set of ids from the configuration file
	 */
	public Set<String> getIDs()
	{
		Set<String> scannerIds = new HashSet<>();
		for (Map.Entry<Object, Object> entry : properties.entrySet())
		{
			String key = (String)entry.getKey();
			String[] splitKey = key.split("\\.");
			if (splitKey.length < 2)
			{
				throw new IllegalArgumentException(
					"Key [" + key + "] inside " + AntivirusProcessor.getAvScannerConfFilePath()
						+ " cannot be resolved.");
			}
			scannerIds.add(splitKey[0]);
		}
		return scannerIds;
	}

	/**
	 * Reads a properties file and returns a {@link Properties} object with the file's contents.
	 *
	 * @param file The file path of the <code>avScanner.properties</code> file
	 * @return The properties as a key-value Map
	 */
	private Properties getPropertiesFromFile(String file)
	{
		File propFile = new File(file);
		String errorMsg = "The file \"" + propFile.getAbsolutePath();
		if (!propFile.exists())
		{
			logger.error(errorMsg + "\" does not exist.");
			return null;
		}

		if (!propFile.isFile())
		{
			logger.error(errorMsg
				+ "\" is actually not a regular file! Cannot be used as configuration file for this program. ");
			return null;
		}

		if (!propFile.canRead())
		{
			logger.error(errorMsg + "\" cannot be read!");
			return null;
		}

		try (InputStream is = new FileInputStream(propFile))
		{
			Properties props = new Properties();
			props.load(is);
			return props;
		}
		catch (IOException ioe)
		{
			String message =
				"Error while loading properties from file \"" + propFile.getAbsolutePath() + "\" (" + ioe + ").";
			logger.error(message, ioe);
			throw new IllegalArgumentException(message);
		}
	}

	/**
	 * Gets the properties for each id
	 *
	 * @return A map of ids and properties associated with that ids
	 */
	public Map<String, Properties> getKeyValuePairsById()
	{
		Set<String> scannerIds = getIDs();
		Map<String, Properties> propertiesMap = new HashMap<>();
		Properties keyValuePairs;
		Enumeration<String> enums = (Enumeration<String>)properties.propertyNames();
		for (String id : scannerIds)
		{
			keyValuePairs = new Properties();
			while (enums.hasMoreElements())
			{
				String key = enums.nextElement();
				String[] splitKey = key.split("\\.");
				if (id.equalsIgnoreCase(splitKey[0]))
				{
					String value = properties.getProperty(key);
					keyValuePairs.put(splitKey[1], value);
				}
			}
			propertiesMap.put(id, keyValuePairs);
		}
		return propertiesMap;
	}

	/**
	 * Iterates through the property list and checks for the presence and the value of the {@link PropertyKey}
	 *
	 * @param properties The map of key-value properties for one scanner
	 * @return A list of {@link PropertyKey} which are not in the properties list or have invalid values
	 */
	public List<PropertyKey> validateAndGetInvalidList(Properties properties)
	{
		List<PropertyKey> result = new ArrayList<>();
		for (PropertyKey key : PropertyKey.values())
		{
			if (!properties.containsKey(key.getPropertyName()))
			{
				result.add(key);
			}
			else
			{
				String value = properties.getProperty(key.getPropertyName());
				if (key.getValidationStrategy() != null)
				{
					boolean isValid = key.getValidationStrategy().validate(value);
					if (!isValid)
						result.add(key);
				}
			}
		}
		return result;
	}

	/**
	 * Iterates through the property list and checks for the presence and the value of the {@link PropertyKey}
	 *
	 * @param properties The map of key-value properties for one scanner
	 * @return A list of {@link PropertyKey} which are in the properties list and have valid values
	 */
	public Properties validateAndGetValidList(Properties properties)
	{
		Properties result = new Properties();
		for (PropertyKey key : PropertyKey.values())
		{
			if (properties.containsKey(key.getPropertyName()))
			{
				String value = properties.getProperty(key.getPropertyName());
				if (key.getValidationStrategy() != null)
				{
					boolean isValid = key.getValidationStrategy().validate(value);
					if (isValid)
						result.put(key.getPropertyName(), properties.getProperty(key.getPropertyName()));
				}
				else
					result.put(key.getPropertyName(), properties.getProperty(key.getPropertyName()));
			}
		}
		return result;
	}

	/**
	 * Iterates through the list of {@link PropertyKey} that are missing or have invalid values and gets the ones that don't have default values
	 *
	 * @param keys The list of {@link PropertyKey} that are missing or have invalid values
	 * @return A list of {@link PropertyKey} which are in the list of {@link PropertyKey} that are missing or have invalid values and don't have default values
	 */
	public List<PropertyKey> getMandatoryMissingFieldsNoDefaults(List<PropertyKey> keys)
	{
		List<PropertyKey> result = new ArrayList<>();
		for (PropertyKey key : keys)
		{
			if (key.getValidationStrategy() != null && StringUtil.isNullEmptyOrBlank(key.getDefaultValue()))
				result.add(key);
		}

		return result;
	}

	/**
	 * Iterates through the list of {@link PropertyKey} that are missing or have invalid values and gets the ones that have default values
	 *
	 * @param keys The list of {@link PropertyKey} that are missing or have invalid values
	 * @return A list of {@link PropertyKey} which are in the list of {@link PropertyKey} that are missing or have invalid values and have default values
	 */
	public List<PropertyKey> getMandatoryMissingFieldsWithDefaults(List<PropertyKey> keys)
	{
		List<PropertyKey> result = new ArrayList<>();
		for (PropertyKey key : keys)
		{
			if (key.getValidationStrategy() != null && !StringUtil.isNullEmptyOrBlank(key.getDefaultValue()))
				result.add(key);
		}

		return result;
	}

	/**
	 * Iterates through the list of {@link PropertyKey} that are missing or have invalid values and returns the ones that have a validation strategy
	 *
	 * @param keys The list of {@link PropertyKey} that are missing or have invalid values
	 * @return A list of {@link PropertyKey} which are in the list of {@link PropertyKey} that are missing or have invalid values and don't have a validation strategy
	 */
	public List<PropertyKey> getMissingRestrictionFields(List<PropertyKey> keys)
	{
		List<PropertyKey> result = new ArrayList<>();
		for (PropertyKey key : keys)
		{
			if (key.getValidationStrategy() == null)
				result.add(key);
		}

		return result;
	}
}
