package com.axway.antivirus.tests.configuration;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.tests.tools.PropertyFileUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

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
		pathToGeneratedConfFile = new PropertyFileUtils().getPathToGeneratedFile();
		avConfManager = AntivirusConfigurationManager.getInstance();
		avConfManager.setConfLoaded(false);
		avConfHolder = avConfManager.getScannerConfiguration(new PropertyFileUtils().getPathToTemplateFile());
	}

	@After
	public void cleanAfterTests()
	{
		File clientRequests = new File(new PropertyFileUtils().getPathToGeneratedFile());
		clientRequests.delete();
	}

	@Test
	public void noHostnameTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "hostname", "");
		avConfManager.setConfLoaded(false);
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noPortTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "port", "");
		avConfManager.setConfLoaded(false);
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noServiceTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "service", "");
		avConfManager.setConfLoaded(false);
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noICAPServerVersionTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "ICAPServerVersion", "");
		avConfManager.setConfLoaded(false);
		assertNull(avConfManager.getScannerConfiguration(propFile.getCanonicalPath()));
	}

	@Test
	public void noPreviewSizeTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "previewSize", "");
		avConfManager.setConfLoaded(false);
		//If not set, the default value <1024> is used
		assertEquals(1024, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getPreviewSize());
	}

	@Test
	public void noStdSendLengthTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "stdSendLength", "");
		avConfManager.setConfLoaded(false);
		//If not set, the default value <8192> is used
		assertEquals(8192, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getStdSendLength());
	}

	@Test
	public void noStdReceiveLengthTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "stdSendLength", "");
		avConfManager.setConfLoaded(false);
		//If not set, the default value <8192> is used
		assertEquals(8192, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getStdReceiveLength());
	}

	@Test
	public void noConnectionTimeoutTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "connectionTimeout", "");
		avConfManager.setConfLoaded(false);
		//if no connection timeout is specified, the default value <10000> is returned
		assertEquals(10000, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getConnectionTimeout());
	}

	@Test
	public void noRejectFileOnErrorValueTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "rejectFileOnError", "");
		avConfManager.setConfLoaded(false);
		//if no value is specified, the default value <true> is returned
		assertEquals(true, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).isRejectFileOnError());
	}

	@Test
	public void noScanFromIntegratorValueTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "scanFromIntegrator", "");
		avConfManager.setConfLoaded(false);
		//if no value is specified, the default value <false> is returned
		assertEquals(false, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).isScanFromIntegrator());
	}

	@Test
	public void noMaxFileSizeValueTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "maxFileSize", "");
		avConfManager.setConfLoaded(false);
		//if no value is specified, the default value <-1> is returned
		assertEquals(-1, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getMaxFileSize());
	}

	@Test
	public void noFileNameRestrictionTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "fileNameRestriction", "");
		avConfManager.setConfLoaded(false);
		assertEquals(0, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getFilenameRestrictions().size());
	}

	@Test
	public void noFileExtensionRestrictionTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "fileExtensionRestriction", "");
		avConfManager.setConfLoaded(false);
		assertEquals(0, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getFileExtensionRestriction().size());
	}

	@Test
	public void noProtocolRestrictionTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "protocolRestriction", "");
		avConfManager.setConfLoaded(false);
		assertEquals(0, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getProtocolRestrictions().size());
	}

	@Test
	public void noPartnerRestrictionsTest() throws IOException
	{
		PropertyFileUtils propUtil = new PropertyFileUtils();
		File propFile = propUtil.makeFile(pathToGeneratedConfFile, "partnerNameRestriction", "");
		avConfManager.setConfLoaded(false);
		assertEquals(0, avConfManager.getScannerConfiguration(propFile.getCanonicalPath()).getRestrictedPartners().size());
	}

}
