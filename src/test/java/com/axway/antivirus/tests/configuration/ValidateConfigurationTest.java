package com.axway.antivirus.tests.configuration;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.tests.tools.PropertyFileUtils;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNull;

public class ValidateConfigurationTest
{
	private static AntivirusConfigurationManager avConfManager;
	private static AntivirusConfigurationHolder avConfHolder;
	private static String pathToGeneratedConfFile;

	@Before
	public void setUp()
	{
		String pathToTemplateConfFile =
			Paths.get(".").toAbsolutePath().normalize().toString() + File.separator + "src" + File.separator + "test"
				+ File.separator + "java" + File.separator + "com/axway/antivirus/tests/resources" + File.separator + "avScanner.properties";
		pathToGeneratedConfFile =
			Paths.get(".").toAbsolutePath().normalize().toString() + File.separator + "src" + File.separator + "test"
				+ File.separator + "java" + File.separator + "com/axway/antivirus/tests/resources" + File.separator + "avScanner2.properties";

		avConfManager = AntivirusConfigurationManager.getInstance();
		avConfManager.setConfLoaded(false);
		avConfHolder = avConfManager.getScannerConfiguration(pathToTemplateConfFile);
	}

	@Test
	public void noPortTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile,"port", "");
		avConfManager.setConfLoaded(false);
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noHostnameTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile,"hostname", "");
		avConfManager.setConfLoaded(false);
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noPartnerRestrictionsTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile,"partnerNameRestriction", "");
		avConfManager.setConfLoaded(false);
		assertEquals(0, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getRestrictedPartners().size());
	}

	@Test
	public void noConnectionTimeoutTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile,"connectionTimeout", "");
		avConfManager.setConfLoaded(false);
		//if no connection timeout is specified, the default value <10000> is returned
		assertEquals(10000, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getConnectionTimeout());
	}
}
