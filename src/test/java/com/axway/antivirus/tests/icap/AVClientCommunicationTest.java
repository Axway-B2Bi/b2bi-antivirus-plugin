package com.axway.antivirus.tests.icap;

import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.icap.AntivirusClient;
import com.axway.antivirus.tests.tools.InjectionUtils;
import com.axway.antivirus.tests.tools.PrepareForTests;
import com.axway.antivirus.tests.tools.PropertyFileUtils;

import org.junit.After;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.io.FileUtils;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class AVClientCommunicationTest
{

	@Test
	public void scanFile_Response_Clean_Test() throws NoSuchFieldException, IllegalAccessException, IOException,
		AntivirusException
	{
		String firstResponse = new PropertyFileUtils().getIcapInputFilesFolderPath() + "serverResponses_cleanFile.txt";
		AntivirusClient sut = PrepareForTests.prepareRealClient();
		DataOutputStream dos = new DataOutputStream(new FileOutputStream(
			new PropertyFileUtils().getIcapInputFilesFolderPath() + "clientRequest.txt"));
		DataInputStream dis = new DataInputStream(new FileInputStream(firstResponse));

		int previewSize = 512;
		InjectionUtils.injectField(sut, AntivirusClient.class, "stdPreviewSize", previewSize);
		InjectionUtils.injectField(sut, AntivirusClient.class, "out", dos);
		InjectionUtils.injectField(sut, AntivirusClient.class, "in", dis);

		assertTrue(sut.scanFile(new File(new PropertyFileUtils().getPathToTemplateFile())));
	}

	@Test
	public void scanFile_Response_Infected_Test() throws NoSuchFieldException, IllegalAccessException, IOException,
		AntivirusException
	{
		String firstResponse =
			new PropertyFileUtils().getIcapInputFilesFolderPath() + "serverResponses_infectedFile.txt";
		AntivirusClient sut = PrepareForTests.prepareRealClient();
		DataOutputStream dos = new DataOutputStream(new FileOutputStream(
			new PropertyFileUtils().getIcapInputFilesFolderPath() + "clientRequest.txt"));
		DataInputStream dis = new DataInputStream(new FileInputStream(firstResponse));

		int previewSize = 512;
		InjectionUtils.injectField(sut, AntivirusClient.class, "stdPreviewSize", previewSize);
		InjectionUtils.injectField(sut, AntivirusClient.class, "out", dos);
		InjectionUtils.injectField(sut, AntivirusClient.class, "in", dis);

		assertFalse(sut.scanFile(new File(new PropertyFileUtils().getPathToTemplateFile())));
		assertEquals("X-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;X-Virus-ID: Eicar-Test-Signature", sut.getFailureReason().toString());
	}

	@Test(expected = AntivirusException.class)
	public void scanFile_Corrupt_Response_Test() throws NoSuchFieldException, IllegalAccessException, IOException,
		AntivirusException
	{
		String firstResponse =
			new PropertyFileUtils().getIcapInputFilesFolderPath() + "serverResponses_corruptResponse.txt";
		AntivirusClient sut = PrepareForTests.prepareRealClient();
		DataOutputStream dos = new DataOutputStream(new FileOutputStream(
			new PropertyFileUtils().getIcapInputFilesFolderPath() + "clientRequest.txt"));
		DataInputStream dis = new DataInputStream(new FileInputStream(firstResponse));

		int previewSize = 512;
		InjectionUtils.injectField(sut, AntivirusClient.class, "stdPreviewSize", previewSize);
		InjectionUtils.injectField(sut, AntivirusClient.class, "out", dos);
		InjectionUtils.injectField(sut, AntivirusClient.class, "in", dis);
		sut.scanFile(new File(new PropertyFileUtils().getPathToTemplateFile()));
	}

	@Test
	public void scanFile_Client_Request_Test() throws NoSuchFieldException, IllegalAccessException, IOException,
		AntivirusException
	{
		String firstResponse = new PropertyFileUtils().getIcapInputFilesFolderPath() + "serverResponses_cleanFile.txt";
		AntivirusClient sut = PrepareForTests.prepareRealClient();
		DataOutputStream dos = new DataOutputStream(new FileOutputStream(
			new PropertyFileUtils().getIcapInputFilesFolderPath() + "clientRequest.txt"));
		DataInputStream dis = new DataInputStream(new FileInputStream(firstResponse));

		int previewSize = 512;
		InjectionUtils.injectField(sut, AntivirusClient.class, "stdPreviewSize", previewSize);
		InjectionUtils.injectField(sut, AntivirusClient.class, "out", dos);
		InjectionUtils.injectField(sut, AntivirusClient.class, "in", dis);
		sut.scanFile(new File(new PropertyFileUtils().getPathToTemplateFile()));
		dos.close();

		File clientRequests = new File(new PropertyFileUtils().getIcapInputFilesFolderPath() + "clientRequest.txt");
		File clientRequestsTemplate = new File(
			new PropertyFileUtils().getIcapInputFilesFolderPath() + "clientRequest_template.txt");

		assertTrue(FileUtils.contentEquals(clientRequests, clientRequestsTemplate));
	}

	@After
	public void cleanAfterTests()
	{
		File clientRequests = new File(new PropertyFileUtils().getIcapInputFilesFolderPath() + "clientRequest.txt");
		clientRequests.delete();
	}

}
