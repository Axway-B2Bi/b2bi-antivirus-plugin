package com.axway.antivirus.tests.configuration;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.tests.tools.PropertyFileUtils;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ReadConfigurationTest
{
	private static AntivirusConfigurationHolder avHolder;
	private static AntivirusConfigurationManager avConfManager;

	@Before
	public void setUp()
	{
		avConfManager = AntivirusConfigurationManager.getInstance();
		avConfManager.setConfLoaded(false);
		avHolder = avConfManager.getScannerConfiguration(new PropertyFileUtils().getPathToTemplateFile());

	}

	@Test
	public void hostnameTest()
	{
		assertEquals("127.0.0.1", avHolder.getHostname());
	}

	@Test
	public void portTest()
	{
		assertEquals(1344, avHolder.getPort());
	}

	@Test
	public void serviceNameTest()
	{
		assertEquals("servicename", avHolder.getService());
	}

	@Test
	public void serverVersionTest()
	{
		assertEquals("1.0", avHolder.getICAPServerVersion());
	}

	@Test
	public void previewSizeTest()
	{
		assertEquals(1024, avHolder.getPreviewSize());
	}

	@Test
	public void stdSendLengthTest()
	{
		assertEquals(8192, avHolder.getStdSendLength());
	}

	@Test
	public void stdReceiveLengthTest()
	{
		assertEquals(8192, avHolder.getStdReceiveLength());
	}

	@Test
	public void connectionTimeoutTest()
	{
		assertEquals(2000, avHolder.getConnectionTimeout());
	}

	@Test
	public void rejectFileOnErrorTest()
	{
		assertTrue(avHolder.isRejectFileOnError());
	}

	@Test
	public void scanFromIntegratorTest()
	{
		assertFalse(avHolder.isScanFromIntegrator());
	}

	@Test
	public void maxFileSizeTest()
	{
		assertEquals(600000, avHolder.getMaxFileSize());
	}

	@Test
	public void rejectFileOverMaxSizeTest()
	{
		assertEquals(false, avHolder.isRejectFileOverMaxSize());
	}

	@Test
	public void fileNameRestrictionTest()
	{
		assertTrue(avHolder.getFilenameRestrictions().contains("filename1.txt"));
	}

	@Test
	public void fileExtensionRestrictionTest()
	{
		assertEquals(2, avHolder.getFileExtensionRestriction().size());
		assertTrue(avHolder.getFileExtensionRestriction().contains("jpg"));
		assertTrue(avHolder.getFileExtensionRestriction().contains("pdf"));
	}

	@Test
	public void protocolRestrictionTest()
	{
		assertEquals(3, avHolder.getProtocolRestrictions().size());
		assertTrue(avHolder.getProtocolRestrictions().contains("AS2"));
		assertTrue(avHolder.getProtocolRestrictions().contains("PGP"));
		assertTrue(avHolder.getProtocolRestrictions().contains("RAW"));
	}

	@Test
	public void partnerNameRestrictionTest()
	{
		assertEquals(2, avHolder.getRestrictedPartners().size());
		assertTrue(avHolder.getRestrictedPartners().contains("Partner Name 1"));
		assertTrue(avHolder.getRestrictedPartners().contains("PartnerName2"));
	}
}