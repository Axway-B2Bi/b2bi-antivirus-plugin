// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.configuration;

import java.io.File;

public class Constants
{
	private Constants()
	{
	}

	/**
	 * OS specific file separator
	 */
	public static final String FS = File.separator;

	/** Scanner config props **/

	/**
	 * <code>SCANNERID.hostname</code> property inside the avScanner.properties file.
	 * <p>IP-address of the ICAP server</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_HOSTNAME = "hostname";

	/**
	 * <code>SCANNERID.port</code> property inside the avScanner.properties file.
	 * <p>ICAP Protocol Service port</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PORT = "port";

	/**
	 * <code>SCANNERID.service</code> property inside the avScanner.properties file
	 * <p>ICAP Service name</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_SERVICE = "service";

	/**
	 * <code>SCANNERID.ICAPServerVersion</code> property inside the avScanner.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_ICAP_SERVER_VERSION = "ICAPServerVersion";

	/**
	 * <code>SCANNERID.previewSize</code> property inside the avScanner.properties file
	 * <p>The preview size is given by the ICAP server.
	 * The value set in 'antivirusID.previewSize' is taken into consideration only if it is smaller than the value given by the server.</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PREVIEW_SIZE = "previewSize";

	/**
	 * <code>SCANNERID.stdReceiveLength</code> property inside the avScanner.properties file
	 * <p>Parameter used for defining the chunk size when receiving from the ICAP server</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_STANDARD_RECEIVE_LENGTH = "stdReceiveLength";

	/**
	 * <code>SCANNERID.stdSendLength</code> property inside the avScanner.properties file
	 * <p>Parameter used for defining the chunk size when sending to the ICAP server</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_STANDARD_SEND_LENGTH = "stdSendLength";

	/**
	 * <code>SCANNERID.connectionTimeout</code> property inside the avScanner.properties file
	 * <p>The value set for the connection timeout is specified in milliseconds
	 * If not set it will revert to the default value: <code>10000</code></p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT = "connectionTimeout";

	/**
	 * <code>SCANNERID.rejectFileOnError</code> property inside the avScanner.properties file
	 * <p>If not set it will revert to the default value: <code>true</code></p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR = "rejectFileOnError";

	/**
	 * <code>SCANNERID.scanFromIntegrator</code> property inside the avScanner.properties file
	 * <p>If not set it will revert to the default value; <code>false</code></p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_SCAN_FROM_INTEGRATOR = "scanFromIntegrator";

	/**
	 * <code>SCANNERID.maxFileSize</code> property inside the avScanner.properties file
	 * <p>If a file has more bytes than the value set in 'maxFileSize' property it won't be scanned</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_MAX_FILE_SIZE = "maxFileSize";

	/**
	 * <code>SCANNERID.rejectFileOverMaxSize</code> property inside the avScanner.properties file
	 * <p>If true, and a file has more bytes than the value set in 'maxFileSize' property, the message will be rejected</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_REJECT_OVER_MAX_FILE_SIZE = "rejectFileOverMaxSize";

	/**
	 * <code>SCANNERID.fileNameRestriction</code> property inside the avScanner.properties file
	 * <p>The file names mentioned in 'fileNameRestriction' property won't be scanned</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_FILENAME_RESTRICTION = "fileNameRestriction";

	/**
	 * <code>SCANNERID.fileExtensionRestriction</code> property inside the avScanner.properties file
	 * <p>The messages having the extension mentioned in 'fileExtensionRestriction' property, won't be scanned</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_FILE_EXTENSION_RESTRICTION = "fileExtensionRestriction";

	/**
	 * <code>SCANNERID.protocolRestriction</code> property inside the avScanner.properties file
	 * <p>All the messages that go through protocols mentioned in 'protocolRestriction' property won't be scanned</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PROTOCOL_RESTRICTION = "protocolRestriction";

	/**
	 * <code>SCANNERID.partnerNameRestriction</code> property inside the avScanner.properties file
	 * <p>All the messages from trading partners mentioned in 'partnerNameRestriction' property won't be scanned</p>
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PARTNER_NAME_RESTRICTION = "partnerNameRestriction";

}
