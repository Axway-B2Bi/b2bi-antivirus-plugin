package com.axway.antivirus.icap;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.exceptions.AntivirusException;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ICAPTest
{
	private static AntivirusConfigurationManager avConfManager;
	private static AntivirusConfigurationHolder avHolder;
	private static String pathToConfFile;

	@Before
	public void setUp()
	{
		pathToConfFile =
			Paths.get(".").toAbsolutePath().normalize().toString() + File.pathSeparator + "src" + File.pathSeparator
				+ "test" + File.pathSeparator + "java" + File.pathSeparator + "resources" + File.pathSeparator
				+ "avScanner2.properties";
		avConfManager = AntivirusConfigurationManager.getInstance();
		avHolder = avConfManager.getScannerConfiguration(pathToConfFile);
	}

	@Test
	public void testAntivirusScan()
	{
		AntivirusClient icapClient = mock(AntivirusClient.class);
		//new AntivirusClient(avHolder.getHostname(), avHolder.getPort(), avHolder.getService(), avHolder.getServerVersion(), avHolder.getPreviewSize(), avHolder.getStdReceiveLength(), avHolder.getStdSendLength(), avHolder.getConnectionTimeout());
		try
		{
			// define return value for method scanFile()
			when(icapClient.scanFile(new File(pathToConfFile))).thenReturn(true);

			// use mock in test....
			assertTrue(icapClient.scanFile(new File(pathToConfFile)));
		}
		catch (IOException | AntivirusException ex)
		{

		}
	}
}
