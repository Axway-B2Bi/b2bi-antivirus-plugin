package com.axway.antivirus.tests.tools;

import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.icap.AntivirusClient;
import com.cyclonecommerce.api.inlineprocessing.Message;
import com.cyclonecommerce.util.VirtualData;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PrepareForTests
{
	public static Message prepareMessage(long size) throws IOException
	{
		final Message msgMock = mock(Message.class);
		final VirtualData dataMock = mock(VirtualData.class);

		when(dataMock.length()).thenReturn(size);
		when(msgMock.getData()).thenReturn(dataMock);
		when(msgMock.getData().toFile()).thenReturn(new File("testFile.txt"));
		return msgMock;
	}

	public static AntivirusClient prepareClient(boolean isClean, String message) throws IOException, AntivirusException
	{
		final AntivirusClient avClientMock = mock(AntivirusClient.class);
		when(avClientMock.scanFile(any(File.class))).thenReturn(isClean);

		StringBuilder failureReason = new StringBuilder(message);
		when(avClientMock.getFailureReason()).thenReturn(failureReason);

		return avClientMock;
	}

	public static void assertOnList(final List<String> retrievedValues, String... expectedValues)
	{
		assertEquals(retrievedValues.size(), expectedValues.length);
		for (int i = 0; i < retrievedValues.size(); i++)
		{
			assertEquals(expectedValues[i], retrievedValues.get(i));
		}
	}
}
