package com.axway.antivirus.configuration;

import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.inlineprocessor.AntivirusProcessor;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
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

			for (Map.Entry<Object, Object> entry : props.entrySet())
			{
				String key = (String)entry.getKey();
				String value = (String)entry.getValue();
				String[] splitKey = key.split("\\.");
				if (splitKey.length < 2)
				{
					throw new IllegalArgumentException(
						"Key [" + key + "] inside " + AntivirusProcessor.getAvScannerConfFilePath()
							+ " cannot be resolved.");
				}

				scannerId = splitKey[0];
				String propName = splitKey[1];

				AntivirusConfigurationHolder configurationHolder = avServersConfig.get(scannerId);
				if (configurationHolder == null)
				{
					configurationHolder = new AntivirusConfigurationHolder();
					configurationHolder.setScannerId(scannerId);
					avServersConfig.put(scannerId, configurationHolder);
				}
				configurationHolder.addProperty(propName, value);
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

	private Properties getPropertiesFromFile(String file) throws Exception
	{
		File propFile = new File(file);
		if (!propFile.exists())
		{
			logger.error("The file \"" + propFile.getAbsolutePath() + "\" does not exist.");
			return null;
		}

		if (!propFile.isFile())
		{
			logger.error("The file \"" + propFile.getAbsolutePath()
				+ "\" is actually not a regular file! Cannot be used as configuration file for this program. ");
			return null;
		}

		if (!propFile.canRead())
		{
			logger.error("The file \"" + propFile.getAbsolutePath() + "\" cannot be read!");
			return null;
		}
		Properties props = new Properties();
		InputStream is = null;
		try
		{
			is = new FileInputStream(propFile);

			props.load(is);

			return props;
		}
		catch (IOException ioe)
		{
			String message =
				"Error while loading properties from file \"" + propFile.getAbsolutePath() + "\" (" + ioe + ").";
			logger.error(message, ioe);
			throw new Exception(message, ioe);
		}
		finally
		{
			if (is != null)
			{
				try
				{
					is.close();
				}
				catch (IOException ioe)
				{
					String errorString =
						"Error while closing file \"" + propFile.getAbsolutePath() + "\" after reading it ("
							+ ioe.getMessage() + ").";
					logger.warn(errorString, ioe);
				}
			}
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
