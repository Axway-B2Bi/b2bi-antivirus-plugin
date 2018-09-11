package com.axway.antivirus.tests.inlineprocessor;

import com.axway.antivirus.configuration.AntivirusConfigurationHolder;
import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.inlineprocessor.AntivirusProcessor;
import com.axway.antivirus.providers.ExchangePointProvider;
import com.axway.antivirus.tests.tools.PrepareForTests;
import com.axway.antivirus.tests.tools.PropertyFileUtils;
import com.axway.antivirus.tests.tools.ScanDecider;
import com.cyclonecommerce.api.inlineprocessing.Message;

import org.junit.After;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ScanDeciderTest
{
	private ScanDecider setUp(String property, String value, ExchangePointProvider ep) throws IOException
	{
		final PropertyFileUtils propertyFileUtils = new PropertyFileUtils();
		String pathToTestFile = new PropertyFileUtils().getPathToGeneratedFile();
		propertyFileUtils.makeFile(pathToTestFile, property, value);
		AntivirusConfigurationManager.getInstance().setConfLoaded(false);
		final AntivirusConfigurationHolder antivirusConfigurationHolder = AntivirusConfigurationManager.getInstance().getScannerConfiguration(pathToTestFile);
		if (null == ep)
			return new ScanDecider(antivirusConfigurationHolder);
		else
			return new ScanDecider(ep, antivirusConfigurationHolder);
	}

	@After
	public void cleanAfter()
	{
		File clientRequests = new File(new PropertyFileUtils().getPathToGeneratedFile());
		clientRequests.delete();
	}

	@Test
	public void messageSizeRestrictionTest() throws IOException
	{
		final ScanDecider scanDecider = setUp("maxFileSize", "63000", null);
		final Message mockMessage = PrepareForTests.prepareMessage(66000L);
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);

		assertEquals(false, scanDecider.isMessageSizeValid(mockMessage));

		verify(mockMessage, times(1)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());
		PrepareForTests.assertOnList(metaNameCaptor.getAllValues(), "AVScanStatus");
		PrepareForTests.assertOnList(metaValueCaptor.getAllValues(), AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
	}

	@Test
	public void fileNameRestrictionTest() throws IOException
	{
		final ScanDecider scanDecider = setUp("fileNameRestriction", "test_filename.txt", null);
		final Message mockMessage = PrepareForTests.prepareMessage(66L);
		when(mockMessage.getMetadata("ConsumptionFilename")).thenReturn("test_filename.txt");
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);

		assertEquals(false, scanDecider.isFileNameValid(mockMessage));

		verify(mockMessage, times(1)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());
		PrepareForTests.assertOnList(metaNameCaptor.getAllValues(), "AVScanStatus");
		PrepareForTests.assertOnList(metaValueCaptor.getAllValues(), AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
	}

	@Test
	public void fileExtensionRestrictionTest() throws IOException
	{
		final ScanDecider scanDecider = setUp("fileExtensionRestriction", "txt", null);
		final Message mockMessage = PrepareForTests.prepareMessage(66L);
		when(mockMessage.getMetadata("ConsumptionFilenameExtension")).thenReturn(".txt");
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);

		assertEquals(false, scanDecider.isFileExtensionValid(mockMessage));

		verify(mockMessage, times(1)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());
		PrepareForTests.assertOnList(metaNameCaptor.getAllValues(), "AVScanStatus");
		PrepareForTests.assertOnList(metaValueCaptor.getAllValues(), AntivirusProcessor.SCAN_CODES.NOTSCANNED.getValue());
	}
}
