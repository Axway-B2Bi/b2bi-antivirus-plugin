package com.axway.antivirus.configuration;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.file.Paths;
import java.util.List;

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
		String pathToConfFile =
			Paths.get(".").toAbsolutePath().normalize().toString() + File.separator + "src" + File.separator
				+ "test" + File.separator + "java" + File.separator + "resources" + File.separator
				+ "avScanner.properties";
		avConfManager = AntivirusConfigurationManager.getInstance();
		avConfManager.setConfLoaded(false);
		avHolder = avConfManager.getScannerConfiguration(pathToConfFile);

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
		assertEquals("1.0", avHolder.getServerVersion());
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