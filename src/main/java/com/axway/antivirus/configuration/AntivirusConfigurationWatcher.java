package com.axway.antivirus.configuration;

import com.axway.antivirus.inlineprocessor.AntivirusProcessor;
import com.cyclonecommerce.util.file.FileRegistryHelper;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;

import static com.axway.antivirus.util.Constants.FS;

public class AntivirusConfigurationWatcher implements Runnable
{
	private static final Logger logger = Logger.getLogger(AntivirusConfigurationWatcher.class.getName());
	private static WatchService watchService;
	private static AntivirusConfigurationWatcher avWatcherInstance;
	private boolean isFileModified = false;

	private AntivirusConfigurationWatcher()
	{
	}

	/**
	 * This class is a singleton and we don't want anybody to instantiate it.
	 *
	 * @return An instance of this class.
	 */
	public static AntivirusConfigurationWatcher getInstance()
	{
		if (avWatcherInstance == null)
		{
			try
			{
				avWatcherInstance = new AntivirusConfigurationWatcher();
				watchService = FileSystems.getDefault().newWatchService();
			}
			catch (IOException ioex)
			{
				logger.error("Could not get the common folder: " + ioex.getMessage());
			}
		}
		return avWatcherInstance;
	}

	public void run()
	{
		try
		{
			File file = new File(AntivirusProcessor.getAvScannerConfFilePath());
			long lastTimestamp = file.lastModified();
			Path folderPath = Paths.get(
				FileRegistryHelper.getInstance().getCommonDir().getCanonicalPath() + FS + "conf" + FS + "avConf");
			folderPath.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);
			while (true)
			{
				WatchKey watchKey = watchService.take();
				if (watchKey != null)
				{
					for (WatchEvent<?> watchEvent : watchKey.pollEvents())
					{
						final WatchEvent.Kind<?> kind = watchEvent.kind();
						// Overflow event
						if (StandardWatchEventKinds.OVERFLOW == kind)
						{
							continue; // loop
						}
						else if (StandardWatchEventKinds.ENTRY_MODIFY == kind
							&& watchEvent.context().toString().equalsIgnoreCase("avScanner.properties")
							&& lastTimestamp < file.lastModified())
						{
							logger.info(
								"Antivirus configuration changed." + " File affected: " + watchEvent.context() + ".");
							setFileModified(true);
							lastTimestamp = file.lastModified();
						}
						else if (StandardWatchEventKinds.ENTRY_DELETE == kind
							&& watchEvent.context().toString().equalsIgnoreCase("avScanner.properties"))
						{
							logger.error("Antivirus configuration file deleted. Please add the configuration file.");
							AntivirusConfigurationManager.setConfLoaded(false);

						}
					}
					watchKey.reset();

				}
				if (isFileModified())
				{
					AntivirusConfigurationManager.setConfLoaded(false);
					AntivirusConfigurationManager.getInstance().getScannerConfiguration(AntivirusProcessor.getAvScannerConfFilePath());
				}
			}
		}
		catch (InterruptedException | IOException iex)
		{
			logger.error("An exception occurred: " + iex.getMessage());
		}
	}

	public boolean isFileModified()
	{
		return isFileModified;
	}

	public void setFileModified(boolean fileModified)
	{
		isFileModified = fileModified;
	}
}

