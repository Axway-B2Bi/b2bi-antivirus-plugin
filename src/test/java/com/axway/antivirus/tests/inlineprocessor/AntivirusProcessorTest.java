package com.axway.antivirus.tests.inlineprocessor;

import com.axway.antivirus.configuration.AntivirusConfigurationManager;
import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.icap.AntivirusClient;
import com.axway.antivirus.inlineprocessor.AntivirusProcessor;
import com.axway.antivirus.tests.tools.InjectionUtils;
import com.axway.antivirus.tests.tools.PrepareForTests;
import com.axway.antivirus.tests.tools.PropertyFileUtils;
import com.cyclonecommerce.api.inlineprocessing.Message;
import com.cyclonecommerce.collaboration.MetadataDictionary;

import org.junit.After;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.axway.antivirus.inlineprocessor.AntivirusProcessor.AV_SCAN_INFO;
import static com.axway.antivirus.inlineprocessor.AntivirusProcessor.AV_SCAN_STATUS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AntivirusProcessorTest
{
	@Test
	public void nullConfigurationTest() throws IOException
	{
		AntivirusProcessor antivirusProcessor = new AntivirusProcessor();
		final Message msgMock = PrepareForTests.prepareMessage(45L);

		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);

		antivirusProcessor.process(msgMock);

		verify(msgMock, times(2)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());

		PrepareForTests.assertOnList(metaNameCaptor.getAllValues(), "AVScanStatus", "AVScanInfo");
		PrepareForTests.assertOnList(metaValueCaptor.getAllValues(), AntivirusProcessor.SCAN_CODES.ERROR.getValue(), "Antivirus configuration file is corrupt; check logs for more details.");
	}

	@Test
	public void cleanMessageTest() throws NoSuchFieldException, IllegalAccessException, IOException, AntivirusException
	{
		final AntivirusProcessor antivirusProcessorClean = new AntivirusProcessor();
		final AntivirusClient avClientMock = PrepareForTests.prepareClient(true, "");
		final Message msgMock = PrepareForTests.prepareMessage(45L);
		final AntivirusConfigurationManager antivirusConfigurationManager = AntivirusConfigurationManager.getInstance();
		antivirusConfigurationManager.setConfLoaded(false);

		InjectionUtils.injectField(antivirusProcessorClean, AntivirusProcessor.class, "client", avClientMock);
		InjectionUtils.injectField(antivirusProcessorClean, AntivirusProcessor.class, "avManager", antivirusConfigurationManager);
		InjectionUtils.injectField(antivirusProcessorClean, AntivirusProcessor.class, "avScannerConfFilePath", new PropertyFileUtils().getPathToTemplateFile());
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);

		antivirusProcessorClean.process(msgMock);

		verify(msgMock, times(1)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());
		PrepareForTests.assertOnList(metaNameCaptor.getAllValues(), "AVScanStatus");
		PrepareForTests.assertOnList(metaValueCaptor.getAllValues(), AntivirusProcessor.SCAN_CODES.CLEAN.getValue());

	}

	@Test
	public void infectedMessageTest() throws NoSuchFieldException, IllegalAccessException, IOException,
		AntivirusException
	{
		final AntivirusProcessor antivirusProcessorInfected = new AntivirusProcessor();
		final AntivirusClient avClientMock = PrepareForTests.prepareClient(false, "Message infected. Virus found.");
		final Message msgMock = PrepareForTests.prepareMessage(45L);
		final AntivirusConfigurationManager antivirusConfigurationManager = AntivirusConfigurationManager.getInstance();
		antivirusConfigurationManager.setConfLoaded(false);

		InjectionUtils.injectField(antivirusProcessorInfected, AntivirusProcessor.class, "client", avClientMock);
		InjectionUtils.injectField(antivirusProcessorInfected, AntivirusProcessor.class, "avManager", antivirusConfigurationManager);
		InjectionUtils.injectField(antivirusProcessorInfected, AntivirusProcessor.class, "avScannerConfFilePath", new PropertyFileUtils().getPathToTemplateFile());
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);

		antivirusProcessorInfected.process(msgMock);

		verify(msgMock, times(3)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());
		PrepareForTests.assertOnList(metaNameCaptor.getAllValues(), "AVScanInfo", "AVScanStatus", MetadataDictionary.SHOULD_NOT_DISPLAY_VIEW_AND_DOWNLOAD_LINKS);
		PrepareForTests.assertOnList(metaValueCaptor.getAllValues(), "Message Infected - rejecting message. Threat: "
			+ "Message infected. Virus found.", AntivirusProcessor.SCAN_CODES.INFECTED.getValue(), "true");

	}

	@Test
	public void internalDirectionNoScanMessageTest() throws NoSuchFieldException, IllegalAccessException, IOException
	{
		final AntivirusProcessor antivirusProcessorNoScan = new AntivirusProcessor();
		final AntivirusClient avClientMock = mock(AntivirusClient.class);
		final Message msgMock = PrepareForTests.prepareMessage(45L);
		when(msgMock.getMetadata("Direction")).thenReturn("Internal");
		final AntivirusConfigurationManager antivirusConfigurationManager = AntivirusConfigurationManager.getInstance();
		antivirusConfigurationManager.setConfLoaded(false);
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);

		InjectionUtils.injectField(antivirusProcessorNoScan, AntivirusProcessor.class, "client", avClientMock);
		InjectionUtils.injectField(antivirusProcessorNoScan, AntivirusProcessor.class, "avManager", antivirusConfigurationManager);
		InjectionUtils.injectField(antivirusProcessorNoScan, AntivirusProcessor.class, "avScannerConfFilePath", new PropertyFileUtils().getPathToTemplateFile());

		antivirusProcessorNoScan.process(msgMock);

		verify(msgMock, times(0)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());

	}

	@Test
	public void internalDirectionScanMessageTest() throws NoSuchFieldException, IllegalAccessException, IOException,
		AntivirusException
	{
		final AntivirusProcessor antivirusProcessorScan = new AntivirusProcessor();
		final AntivirusClient avClientMock = PrepareForTests.prepareClient(true, "");
		final Message msgMock = PrepareForTests.prepareMessage(45L);
		final AntivirusConfigurationManager antivirusConfigurationManager = AntivirusConfigurationManager.getInstance();
		PropertyFileUtils propertyFileUtils = new PropertyFileUtils();
		String pathToTestFile = new PropertyFileUtils().getPathToGeneratedFile();
		Map<String, String> props = new HashMap<>();
		props.put("scanFromIntegrator", "true");
		propertyFileUtils.makeFile(pathToTestFile, props);
		when(msgMock.getMetadata("Direction")).thenReturn("Internal");

		InjectionUtils.injectField(antivirusProcessorScan, AntivirusProcessor.class, "client", avClientMock);
		InjectionUtils.injectField(antivirusProcessorScan, AntivirusProcessor.class, "avManager", antivirusConfigurationManager);
		InjectionUtils.injectField(antivirusProcessorScan, AntivirusProcessor.class, "avScannerConfFilePath", pathToTestFile);
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);
		antivirusConfigurationManager.setConfLoaded(false);

		antivirusProcessorScan.process(msgMock);

		verify(msgMock, times(1)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());
		PrepareForTests.assertOnList(metaNameCaptor.getAllValues(), "AVScanStatus");
		PrepareForTests.assertOnList(metaValueCaptor.getAllValues(), AntivirusProcessor.SCAN_CODES.CLEAN.getValue());

	}

	@Test
	public void noScanAndRejectOverMessageSizeTest() throws NoSuchFieldException, IllegalAccessException, IOException,
		AntivirusException
	{
		final AntivirusProcessor antivirusProcessorScan = new AntivirusProcessor();
		final AntivirusClient avClientMock = PrepareForTests.prepareClient(true, "");
		final Message msgMock = PrepareForTests.prepareMessage(45L);
		final AntivirusConfigurationManager antivirusConfigurationManager = AntivirusConfigurationManager.getInstance();
		PropertyFileUtils propertyFileUtils = new PropertyFileUtils();
		String pathToTestFile = new PropertyFileUtils().getPathToGeneratedFile();
		Map<String, String> props = new HashMap<>();
		props.put("maxFileSize", "2");
		props.put("rejectFileOverMaxSize", "true");
		propertyFileUtils.makeFile(pathToTestFile, props);
		when(msgMock.getMetadata("Direction")).thenReturn("Outbound");

		InjectionUtils.injectField(antivirusProcessorScan, AntivirusProcessor.class, "client", avClientMock);
		InjectionUtils.injectField(antivirusProcessorScan, AntivirusProcessor.class, "avManager", antivirusConfigurationManager);
		InjectionUtils.injectField(antivirusProcessorScan, AntivirusProcessor.class, "avScannerConfFilePath", pathToTestFile);
		ArgumentCaptor<String> metaNameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> metaValueCaptor = ArgumentCaptor.forClass(String.class);
		antivirusConfigurationManager.setConfLoaded(false);

		antivirusProcessorScan.process(msgMock);

		verify(msgMock, times(3)).setMetadata(metaNameCaptor.capture(), metaValueCaptor.capture());
		List<String> metadataNames = new ArrayList<>();
		metadataNames.add(AV_SCAN_STATUS);
		metadataNames.add(AV_SCAN_INFO);
		metadataNames.add(MetadataDictionary.SHOULD_NOT_DISPLAY_VIEW_AND_DOWNLOAD_LINKS);
		List<String> metadataValues = new ArrayList<>();
		metadataValues.add(AntivirusProcessor.SCAN_CODES.ERROR.getValue());
		metadataValues.add("Message was not scanned due to the antivirus processor configuration. File size is greater than the maxFileSize value.");
		metadataValues.add("true");
		PrepareForTests.assertOnLists(metaNameCaptor.getAllValues(), metadataNames);
		PrepareForTests.assertOnLists(metaValueCaptor.getAllValues(), metadataValues);
		msgMock.getMetadata(AV_SCAN_INFO);

	}

	@After
	public void cleanInjection() throws IllegalAccessException, NoSuchFieldException
	{
		AntivirusConfigurationManager antivirusConfigurationManager = AntivirusConfigurationManager.getInstance();
		AntivirusProcessor antivirusProcessorCleanInj = new AntivirusProcessor();
		InjectionUtils.injectField(antivirusConfigurationManager, AntivirusConfigurationManager.class, "isConfLoaded", false);
		InjectionUtils.injectField(antivirusProcessorCleanInj, AntivirusProcessor.class, "client", null);
		InjectionUtils.injectField(antivirusProcessorCleanInj, AntivirusProcessor.class, "avManager", null);
		InjectionUtils.injectField(antivirusProcessorCleanInj, AntivirusProcessor.class, "avScannerConfFilePath", null);
	}

	@After
	public void cleanAfter()
	{
		File clientRequests = new File(new PropertyFileUtils().getPathToGeneratedFile());
		clientRequests.delete();
	}
}
