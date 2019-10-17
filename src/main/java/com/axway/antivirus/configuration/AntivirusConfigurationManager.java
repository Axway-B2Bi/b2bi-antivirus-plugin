// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.configuration;

import com.axway.antivirus.configuration.util.ConfigUtil;
import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.inlineprocessor.AntivirusProcessor;

import org.apache.log4j.Logger;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class AntivirusConfigurationManager
{
	private static final Logger logger = Logger.getLogger(AntivirusConfigurationManager.class);
	private static volatile AntivirusConfigurationManager instance;
	private static Map<String, AntivirusConfigurationHolder> avServersConfig = new HashMap<>();
	private static String scannerId;
	private static Boolean isConfLoaded = false;

	private AntivirusConfigurationManager()
	{
	}

	/**
	 * This class is a singleton and we don't want anybody to instantiate it.
	 * When the instance for this class is first created the thread that monitors the modifications for the property file is also started
	 *
	 * @return An instance of this class.
	 */
	public static AntivirusConfigurationManager getInstance()
	{
		if (instance == null)
		{
			synchronized (AntivirusConfigurationManager.class)
			{
				if (instance == null)
				{
					instance = new AntivirusConfigurationManager();
					//get the instance for the configuration watcher service and start the thread that monitors the file changes
					Thread thread = new Thread(AntivirusConfigurationWatcher.getInstance());
					thread.start();
				}
			}
		}
		return instance;
	}

	/**
	 * Gets the scanner configuration from the <code>{avScannerConfFilePath}</code> file.
	 * If the configuration is not loaded it loads it, else returns it
	 *
	 * @param pathToFile The file path for the configuration file
	 * @return An instance of the AntivirusConfigurationHolder
	 **/
	public AntivirusConfigurationHolder getScannerConfiguration(String pathToFile)
	{
		if (isConfLoaded() && avServersConfig.size() > 0)
			return avServersConfig.get(scannerId);
		else
		{
			try
			{
				logger.info("Scanner configuration not present or modified - attempting to load it.");
				readScannerConfiguration(pathToFile);
				setConfLoaded(true);
				if (avServersConfig.get(scannerId) != null)
				{
					logger.info("Scanner configuration successfully loaded.");
					if (logger.isDebugEnabled())
						logger.debug(avServersConfig.get(scannerId).toString());
				}
				else
				{
					logger.error("Something went wrong when reading the scanner configuration. Please verify the properties file.");
					setConfLoaded(false);
				}
			}
			catch (AntivirusException e)
			{
				logger.error("Didn't manage to load scanner configuration." + e.getMessage());
				return null;
			}
			return avServersConfig.get(scannerId);
		}
	}

	/**
	 * Reads scanner configuration from the <code>{avScannerConfFilePath}</code> file.
	 *
	 * @throws AntivirusException if an error occurs while reading the scanner configuration.
	 */
	private void readScannerConfiguration(String pathToFile) throws AntivirusException
	{
		try
		{
			ConfigUtil configUtil = new ConfigUtil(pathToFile);
			avServersConfig.clear();
			Map<String, Properties> keyValuePairsById = configUtil.getKeyValuePairsById();
			if (keyValuePairsById != null)
			{
				for (String id : keyValuePairsById.keySet())
				{

					Properties properties = keyValuePairsById.get(id);
					List<PropertyKey> missingProperties = configUtil.validateAndGetInvalidList(properties);
					if (missingProperties.isEmpty())
					{
						scannerId = id;
						AntivirusConfigurationHolder antivirusConfigurationHolder = new AntivirusConfigurationHolder(id, properties);
						avServersConfig.put(id, antivirusConfigurationHolder);
					}
					else
					{
						//check what kind of properties are missing
						//if they are mandatory without default values throw an error and stop the scanning
						//if they are mandatory that have default values show a warning and proceed
						//if they are optional (restrictions) show an info  and proceed
						List<PropertyKey> missingMandatoryNoDefaults = configUtil.getMandatoryMissingFieldsNoDefaults(missingProperties);
						List<PropertyKey> missingMandatoryWithDefaults = configUtil.getMandatoryMissingFieldsWithDefaults(missingProperties);
						List<PropertyKey> missingRestrictionFields = configUtil.getMissingRestrictionFields(missingProperties);
						if (!missingMandatoryNoDefaults.isEmpty()) // mandatory without default values are missing
						{
							logger.error(
								"Mandatory fields missing from properties file. Scanner id: " + id + ", properties: "
									+ Arrays.toString(missingMandatoryNoDefaults.toArray())
									+ ". Please correct the issue.");
							throw new IllegalArgumentException("Mandatory fields have incorrect values or are missing.");
						}
						else
						{
							scannerId = id;
							Properties validKeysFromProperties = configUtil.validateAndGetValidList(properties);
							AntivirusConfigurationHolder avConfHolder = new AntivirusConfigurationHolder(id, validKeysFromProperties);
							avServersConfig.put(scannerId, avConfHolder);

							if (missingMandatoryWithDefaults.contains(PropertyKey.MAX_FILE_SIZE))
							{
								missingRestrictionFields.add(PropertyKey.MAX_FILE_SIZE);
								missingMandatoryWithDefaults.remove(PropertyKey.MAX_FILE_SIZE);
							}
							if (missingMandatoryWithDefaults.contains(PropertyKey.REJECT_OVER_MAX_FILE_SIZE))
							{
								missingRestrictionFields.add(PropertyKey.REJECT_OVER_MAX_FILE_SIZE);
								missingMandatoryWithDefaults.remove(PropertyKey.REJECT_OVER_MAX_FILE_SIZE);
							}
							if (!missingMandatoryWithDefaults.isEmpty()) //  mandatory that have default values
							{
								logger.error(
									"Mandatory fields have incorrect values or are missing. Using default values for scanner id: "
										+ id + " properties: "
										+ Arrays.toString(missingMandatoryWithDefaults.toArray()));
							}
							if (!missingRestrictionFields.isEmpty()) // missing restriction fields
							{
								logger.info("Restriction fields are missing: "
									+ Arrays.toString(missingRestrictionFields.toArray()));
							}
						}
					}
				}
			}
		}
		catch (Exception e)
		{
			String message =
				"The file " + AntivirusProcessor.getAvScannerConfFilePath() + " seems to be corrupt or missing. ";
			throw new AntivirusException(message + e.getMessage());
		}
	}

	/**
	 * Getter for the flag, if the configuration is loaded or not
	 *
	 * @return <code>true</code> or <code>false</code> if the configuration is loaded or not
	 */
	public Boolean isConfLoaded()
	{
		return isConfLoaded;
	}

	/**
	 * Setter for the flag
	 *
	 * @param confLoaded flag set if the configuration is loaded or not
	 */
	public static void setConfLoaded(Boolean confLoaded)
	{
		isConfLoaded = confLoaded;
	}
}
