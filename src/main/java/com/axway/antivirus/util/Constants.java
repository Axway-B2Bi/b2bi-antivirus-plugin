package com.axway.antivirus.util;

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
	 * <code>SCANNERID&gt;.hostname</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_HOSTNAME = "hostname";

	/**
	 * <code>SCANNERID&gt;.port</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PORT = "port";

	/**
	 * <code>SCANNERID&gt;.service</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_SERVICE = "service";

	/**
	 * <code>SCANNERID&gt;.version</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_ICAP_SERVER_VERSION = "ICAPServerVersion";

	/**
	 * <code>SCANNERID&gt;.previewsize</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PREVIEW_SIZE = "previewSize";

	/**
	 * <code>SCANNERID&gt;.stdReceiveLength</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_STANDARD_RECEIVE_LENGTH = "stdReceiveLength";

	/**
	 * <code>SCANNERID&gt;.stdSendLength</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_STANDARD_SEND_LENGTH = "stdSendLength";

	/**
	 * <code>SCANNERID&gt;.connectiontimeout</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_CONNECTION_TIMEOUT = "connectionTimeout";

	/**
	 * <code>SCANNERID&gt;.rejectFileOnError</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_REJECT_FILE_ON_ERROR = "rejectFileOnError";

	/**
	 * <code>SCANNERID&gt;.filenamePattern</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_MAX_FILE_SIZE = "maxFileSize";

	/**
	 * <code>SCANNERID&gt;.filenamePattern</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_FILENAME_RESTRICTION = "fileNameRestriction";

	/**
	 * <code>SCANNERID&gt;.filesizeRestriction</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_FILE_EXTENSION_RESTRICTION = "fileExtensionRestriction";

	/**
	 * <code>SCANNERID&gt;.protocolRestriction</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PROTOCOL_RESTRICTION = "protocolRestriction";

	/**
	 * <code>SCANNERID&gt;.partnerRestriction</code> property inside the antivirus-scanners.properties file
	 */
	public static final String SCANNER_CONFIGURATION_PROPERTY_PARTNER_NAME_RESTRICTION = "partnerNameRestriction";
}
