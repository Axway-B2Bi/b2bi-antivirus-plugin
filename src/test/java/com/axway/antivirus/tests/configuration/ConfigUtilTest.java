package com.axway.antivirus.tests.configuration;

import com.axway.antivirus.configuration.PropertyKey;
import com.axway.antivirus.configuration.util.ConfigUtil;
import com.axway.antivirus.tests.tools.PropertyFileUtils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConfigUtilTest
{
	private static ConfigUtil configUtil;

	@Before
	public void setUp()
	{
		String pathToConfFile = new PropertyFileUtils().getPathToTemplateFile();
		configUtil = new ConfigUtil(pathToConfFile);
	}

	@After
	public void clean()
	{
		configUtil = null;
	}

	@Test
	public void getIdsTest()
	{
		Set<String> ids = configUtil.getIDs();
		assertEquals(2, ids.size());
		assertTrue(ids.contains("antivirusID"));
		assertTrue(ids.contains("antivirusID2"));
	}

	@Test
	public void getKeyValuePairsByIdTest()
	{
		Map<String, Properties> keyValuePairsById = configUtil.getKeyValuePairsById();
		assertEquals(2, keyValuePairsById.keySet().size());
		assertEquals(15, keyValuePairsById.get("antivirusID").size());
	}

	@Test
	public void validateAndGetInvalidListTest()
	{
		List<String> propertyNamesNotIncluded = new ArrayList<>();
		propertyNamesNotIncluded.add("stdSendLength");
		propertyNamesNotIncluded.add("fileNameRestriction");
		Properties properties = makeProperties(propertyNamesNotIncluded);
		List<PropertyKey> invalidPropertyList = configUtil.validateAndGetInvalidList(properties);
		assertEquals(2, invalidPropertyList.size());
	}

	@Test
	public void validateAndGetValidListTest()
	{
		List<String> propertyNamesNotIncluded = new ArrayList<>();
		propertyNamesNotIncluded.add("connectionTimeout");
		propertyNamesNotIncluded.add("protocolRestriction");
		Properties properties = makeProperties(propertyNamesNotIncluded);
		Properties validPropertyList = configUtil.validateAndGetValidList(properties);
		assertEquals(13, validPropertyList.size());
	}

	@Test
	public void getMandatoryMissingFieldsNoDefaultsTest()
	{
		List<String> propertyNamesNotIncluded = new ArrayList<>();
		propertyNamesNotIncluded.add("service");
		propertyNamesNotIncluded.add("partnerNameRestriction");
		Properties properties = makeProperties(propertyNamesNotIncluded);
		List<PropertyKey> missingValues = configUtil.validateAndGetInvalidList(properties);
		List<PropertyKey> mandatoryMissingFields = configUtil.getMandatoryMissingFieldsNoDefaults(missingValues);
		assertEquals(1, mandatoryMissingFields.size());
	}

	@Test
	public void getMandatoryMissingFieldsWithDefaultsTest()
	{
		List<String> propertyNamesNotIncluded = new ArrayList<>();
		propertyNamesNotIncluded.add("previewSize");
		propertyNamesNotIncluded.add("partnerNameRestriction");
		Properties properties = makeProperties(propertyNamesNotIncluded);
		List<PropertyKey> missingValues = configUtil.validateAndGetInvalidList(properties);
		List<PropertyKey> mandatoryMissingFields = configUtil.getMandatoryMissingFieldsWithDefaults(missingValues);
		assertEquals(1, mandatoryMissingFields.size());
	}

	@Test
	public void getMissingRestrictionFieldsTest()
	{
		List<String> propertyNamesNotIncluded = new ArrayList<>();
		propertyNamesNotIncluded.add("scanFromIntegrator");
		propertyNamesNotIncluded.add("partnerNameRestriction");
		Properties properties = makeProperties(propertyNamesNotIncluded);
		List<PropertyKey> missingValues = configUtil.validateAndGetInvalidList(properties);
		List<PropertyKey> missingRestrictions = configUtil.getMissingRestrictionFields(missingValues);
		assertEquals(1, missingRestrictions.size());
	}

	private Properties makeProperties(List<String> propertiesNotIncluded)
	{
		Properties properties = new Properties();
		properties.put("hostname", "127.0.0.1");
		properties.put("port", "1344");
		properties.put("service", "servicename");
		properties.put("ICAPServerVersion", "1.0");
		properties.put("previewSize", "1024");
		properties.put("stdSendLength", "8192");
		properties.put("stdReceiveLength", "8192");
		properties.put("connectionTimeout", "2000");
		properties.put("rejectFileOnError", "true");
		properties.put("scanFromIntegrator", "false");
		properties.put("maxFileSize", "600000");
		properties.put("fileNameRestriction", "filename1.txt");
		properties.put("fileExtensionRestriction", "jpg,pdf");
		properties.put("protocolRestriction", "AS2,PGP,RAW");
		properties.put("partnerNameRestriction", "Partner Name 1,PartnerName2");

		for (String prop : propertiesNotIncluded)
		{
			if (properties.containsKey(prop))
				properties.remove(prop);
		}
		return properties;
	}
}
