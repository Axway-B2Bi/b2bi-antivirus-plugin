package com.axway.antivirus.configuration;

import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.inlineprocessor.AntivirusProcessor;
import com.axway.util.StringUtil;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

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
	 * @return An instance of the AntivirusConfigurationHolder
	 **/
	public AntivirusConfigurationHolder getScannerConfiguration(String pathToFile)
	{
		if (getConfLoaded())
			return avServersConfig.get(scannerId);
		else
		{
			try
			{
				loadConfiguration(pathToFile);
				setConfLoaded(true);
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
	 * Loads the scanner configuration from the <code>{avScannerConfFilePath}</code> file.
	 **/
	private synchronized void loadConfiguration(String pathToFile) throws AntivirusException
	{
		logger.info("Scanner configuration not present or modified - attempting to load it.");
		readScannerConfiguration(pathToFile);
		logger.info("Scanner configuration successfully loaded.");
	}

	/**
	 * Reads scanner configuration from the <code>{avScannerConfFilePath}</code> file.
	 *
	 * @throws AntivirusException if an error occurs while reading system configuration.
	 */
	private void readScannerConfiguration(String pathToFile) throws AntivirusException
	{
		try
		{
			Properties props = getPropertiesFromFile(pathToFile);
			avServersConfig.clear();
			if (props != null)
			{
				Set<String> scannerIds = new HashSet<>();
				for (Map.Entry<Object, Object> entry : props.entrySet())
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
				for (String id : scannerIds)
				{
					AntivirusConfigurationHolder antivirusConfigurationHolder = new AntivirusConfigurationHolder();
					antivirusConfigurationHolder.setScannerId(id);
					for (Map.Entry<Object, Object> entry : props.entrySet())
					{
						String key = (String)entry.getKey();
						String[] splitKey = key.split("\\.");
						if (splitKey[0].equalsIgnoreCase(id))
						{
							String value = (String)entry.getValue();
							antivirusConfigurationHolder.addProperty(splitKey[1], value);
						}
					}
					//check if the mandatory fields exist in the property file
					if (StringUtil.isNullEmptyOrBlank(antivirusConfigurationHolder.getHostname())
						|| 0 == antivirusConfigurationHolder.getPort()
						|| StringUtil.isNullEmptyOrBlank(antivirusConfigurationHolder.getService())
						|| StringUtil.isNullEmptyOrBlank(antivirusConfigurationHolder.getServerVersion())
						|| 0 == antivirusConfigurationHolder.getPreviewSize()
						|| 0 == antivirusConfigurationHolder.getConnectionTimeout()
						|| 0 == antivirusConfigurationHolder.getStdSendLength()
						|| 0 == antivirusConfigurationHolder.getStdReceiveLength())
					{
						logger.error("Mandatory fields missing. Please verify the properties file.");
						throw new AntivirusException("Mandatory fields missing. Please verify the properties file.");
					}
					else
					{
						scannerId = id;
						avServersConfig.put(id, antivirusConfigurationHolder);
					}
				}

			}
		}
		catch (Exception e)
		{
			String message =
				"The file " + AntivirusProcessor.getAvScannerConfFilePath() + " seems to be corrupt or missing. ";
			throw new AntivirusException(message);
		}
	}

	/**
	 * Reads a properties file and returns a {@link Properties} object with the file's contents.
	 */

	private Properties getPropertiesFromFile(String file) throws AntivirusException
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
			throw new AntivirusException(message);
		}
	}

	public Boolean getConfLoaded()
	{
		return isConfLoaded;
	}

	public static void setConfLoaded(Boolean confLoaded)
	{
		isConfLoaded = confLoaded;
	}
}
