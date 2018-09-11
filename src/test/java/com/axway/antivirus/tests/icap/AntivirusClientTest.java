package com.axway.antivirus.tests.icap;

import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.antivirus.icap.AntivirusClient;
import com.axway.antivirus.tests.tools.PrepareForTests;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.ConnectException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AntivirusClientTest
{
	private static final String STATUS_CODE = "StatusCode";
	private static AntivirusClient sut;

	@Before
	public void setUp()
	{
		sut = PrepareForTests.prepareRealClient();
	}

	@Test
	public void interpretStatusCode_100_continue_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "100");
		assertTrue(sut.interpretStatusCode(responseMap));
	}

	@Test
	public void interpretStatusCode_200_options_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "200");
		responseMap.put("Methods", "RESPMOD");
		responseMap.put("Preview", "1024");
		assertTrue(sut.interpretStatusCode(responseMap));
	}

	@Test
	public void interpretStatusCode_200_infected_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "200");
		responseMap.put("X-Threat", "A virus");
		assertFalse(sut.interpretStatusCode(responseMap));
	}

	@Test
	public void interpretStatusCode_204_clean_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "204");
		assertTrue(sut.interpretStatusCode(responseMap));
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_400_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "400");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_404_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "404");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_405_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "405");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_408_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "408");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_500_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "500");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_501_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "501");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_502_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "502");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_503_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "503");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = AntivirusException.class)
	public void interpretStatusCode_505_Test() throws AntivirusException
	{
		Map<String, String> responseMap = new HashMap<>();
		responseMap.put(STATUS_CODE, "505");
		sut.interpretStatusCode(responseMap);
	}

	@Test(expected = ConnectException.class)
	public void connectTest() throws AntivirusException, IOException
	{
		sut.connect();
	}
}
