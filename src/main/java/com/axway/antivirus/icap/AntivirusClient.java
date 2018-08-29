package com.axway.antivirus.icap;

import com.axway.antivirus.exceptions.AntivirusException;
import com.axway.util.StringUtil;

import org.apache.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class AntivirusClient
{
	private static final Logger logger = Logger.getLogger(AntivirusClient.class.getName());
	private static final Charset StandardCharsetsUTF8 = Charset.forName("UTF-8");
	private static final String STATUS_CODE = "StatusCode";
	private static final String USERAGENT = "B2Bi ICAP Client - 1.0";
	private static final String ICAPTERMINATOR = "\r\n\r\n";
	private static final String HTTPTERMINATOR = "0\r\n\r\n";
	private static final String LINETERMINATOR = "\r\n";

	private static final String SERVER_RESPONSE = "Server response: ";

	private Socket client;
	private DataOutputStream out;
	private DataInputStream in;

	private String hostname;
	private int port;
	private String serviceName;
	private String serverVersion;
	private int connectionTimeout;

	private int stdPreviewSize;
	private int stdReceiveLength;
	private int stdSendLength;

	private StringBuilder failureReason;

	/**
	 * @param hostname The IP address to connect to.
	 * @param serverPort The port in the host to use.
	 * @param serviceName The service to use (eg. "squidclamav").
	 * @param version The version of the ICAP server
	 * @param stdPreviewSize The preview size taken into account only if it's smaller than the one gotten from the server (returned by getOptions() method)
	 * @param standardReceiveLength The length of the chunk received from the ICAP server, used in getHeader() method.
	 * @param standardSendLength The length of the chunk sent to the ICAP server, used for splitting the message in chunks
	 * @param connectionTimeout The time to wait for a connection to the ICAP server in milliseconds
	 */
	public AntivirusClient(String hostname, int serverPort, String serviceName, String version, int stdPreviewSize,
		int standardReceiveLength, int standardSendLength, int connectionTimeout)
	{
		this.serviceName = serviceName;
		this.hostname = hostname;
		this.port = serverPort;
		this.serverVersion = version;
		this.stdPreviewSize = stdPreviewSize;
		this.stdReceiveLength = standardReceiveLength;
		this.stdSendLength = standardSendLength;
		this.connectionTimeout = connectionTimeout;
	}

	/**
	 * Initializes the socket connection and IO streams. It asks the server for the available options and
	 * changes settings to match it.
	 *
	 * @throws IOException
	 * @throws AntivirusException
	 **/
	public void connect() throws IOException, AntivirusException
	{
		//Initialize connection
		if ((client = new Socket(this.hostname, port)) == null)
		{
			throw new AntivirusException("Could not open socket connection.");
		}
		//set the connection timeout
		client.setSoTimeout(this.connectionTimeout);

		//Openening out stream
		OutputStream outToServer = client.getOutputStream();
		out = new DataOutputStream(outToServer);

		//Openening in stream
		InputStream inFromServer = client.getInputStream();
		in = new DataInputStream(inFromServer);

		//Asks for the servers available options and returns the raw response as a String.
		String parseMe = getOptions();

		//HashMap of the key-value pairs of the response
		Map<String, String> responseMap = parseHeader(parseMe);
		//Get the value of the Connection property (if present) from the header.
		//If an error occurred then the value should be "close" and we should close the connection
		if (responseMap.containsKey("Connection") && responseMap.get("Connection").equalsIgnoreCase("close"))
			disconnect();

		//Interpret the status code and if it is 200, get the preview size from the response
		interpretStatusCode(responseMap);
	}

	/**
	 * Given a file, it will send the file to the server and return true,
	 * if the server accepts the file. Visa-versa, false if the server rejects it.
	 *
	 * @param file Relative or absolute filepath to a file.
	 * @return Returns true when no infection is found.
	 */
	public boolean scanFile(File file) throws IOException, AntivirusException
	{
		try (FileInputStream fileInStream = new FileInputStream(file))
		{
			int chunkNumber = 1;
			int fileSize = fileInStream.available();
			Map<String, String> responseMap = new HashMap<>();

			//First part of header
			String resBody = "Content-Length: " + fileSize + ICAPTERMINATOR;

			int previewSize = stdPreviewSize;
			if (fileSize <= stdPreviewSize)
			{
				previewSize = fileSize;
			}

			String requestBuffer =
				"RESPMOD icap://" + hostname + "/" + serviceName + " ICAP/" + serverVersion + LINETERMINATOR + "Host: "
					+ hostname + LINETERMINATOR + "User-Agent: " + USERAGENT + LINETERMINATOR + "Allow: 204"
					+ LINETERMINATOR + "Preview: " + previewSize + LINETERMINATOR + "Encapsulated: res-hdr=0, res-body="
					+ resBody.length() + ICAPTERMINATOR + resBody + Integer.toHexString(previewSize) + LINETERMINATOR;

			//tell to ICAP server how you will send the file and the actual size of the file
			sendString(requestBuffer);
			if (logger.isDebugEnabled())
				logger.debug("Sending the preview.");
			if (logger.isTraceEnabled())
				logger.trace("Preview: " + requestBuffer);

			//Sending preview or, if it is smaller than previewSize, the whole file.
			byte[] chunk = new byte[previewSize];
			fileInStream.read(chunk);

			if (logger.isDebugEnabled())
			{
				logger.debug("Sending chunk number: " + chunkNumber + " - " + chunk.length + " bytes");
				chunkNumber++;
			}
			if (logger.isTraceEnabled())
			{
				String chunkString = new String(chunk, StandardCharsetsUTF8);
				logger.trace("Chunk sent: " + chunkString);
			}

			//send the file
			sendBytes(chunk);
			sendString(LINETERMINATOR);

			//if the filesize is less or equal than the preview size send the ieof flag
			if (fileSize <= previewSize)
			{
				sendString("0; ieof" + ICAPTERMINATOR);
				if (logger.isDebugEnabled())
					logger.debug("Sending the ieof flag.");
			}
			else if (previewSize != 0)
			{
				sendString(HTTPTERMINATOR);
				if (logger.isDebugEnabled())
					logger.debug("Sending the end of preview flag and waiting for the server response.");
			}

			// Parse the response! It might not be "100 continue"
			// if fileSize < previewSize, then this is actually the response
			// otherwise it is a "go" for the rest of the file.
			if (fileSize > previewSize)
			{
				String parseMe = getHeader(ICAPTERMINATOR);
				responseMap = parseHeader(parseMe);
				//Get the value of the Connection property (if present) from the header.
				//If an error occurred then the value should be "close" and we should close the connection
				if (responseMap.containsKey("Connection") && responseMap.get("Connection").equalsIgnoreCase("close"))
					disconnect();
				if (logger.isDebugEnabled())
					logger.debug("Received server response after preview.");
				//check to see if the status code is : 100 Continue
				//if it is 100, send the rest of the file
				// else interpret response
				Boolean isContinue = interpretStatusCode(responseMap);
				if (isContinue)
				{//Sending remaining part of file
					byte[] buffer = new byte[stdSendLength];
					int bytesRead;
					while ((bytesRead = fileInStream.read(buffer)) != -1)
					{
						sendString(Integer.toHexString(buffer.length) + LINETERMINATOR);
						if (logger.isDebugEnabled())
						{
							logger.debug("Sending chunk number: " + chunkNumber + " - " + bytesRead + " bytes.");
							chunkNumber++;
						}
						if (logger.isTraceEnabled())
						{
							String bufferString = new String(buffer, StandardCharsetsUTF8);
							logger.trace("Chunk sent: " + bufferString);
						}
						sendBytes(buffer);
						sendString(LINETERMINATOR);
					}
				}
				else
					return false;
				//Closing file transfer.
				requestBuffer = HTTPTERMINATOR;
				if (logger.isDebugEnabled())
					logger.debug("Closing the transfer. ");
				sendString(requestBuffer);
			}

			responseMap.clear();

			String response = getHeader(ICAPTERMINATOR);
			responseMap = parseHeader(response);
			//Get the value of the Connection property (if present) from the header.
			//If an error occurred then the value should be "close" and we should close the connection
			if (responseMap.containsKey("Connection") && responseMap.get("Connection").equalsIgnoreCase("close"))
				disconnect();
			if (logger.isTraceEnabled())
				logger.trace(SERVER_RESPONSE + response);
			return interpretStatusCode(responseMap);
		}

	}

	/**
	 * Automatically asks for the servers available options and returns the raw response as a String.
	 *
	 * @return String of the servers response.
	 * @throws IOException
	 * @throws AntivirusException
	 */
	private String getOptions() throws IOException, AntivirusException
	{
		//Send OPTIONS header and receive response
		//Sending and recieving
		String requestHeader =
			"OPTIONS icap://" + hostname + "/" + serviceName + " ICAP/" + serverVersion + LINETERMINATOR + "Host: "
				+ hostname + LINETERMINATOR + "User-Agent: " + USERAGENT + LINETERMINATOR + "Encapsulated: null-body=0"
				+ ICAPTERMINATOR;

		sendString(requestHeader);

		return getHeader(ICAPTERMINATOR);
	}

	/**
	 * Receive an expected ICAP header as response of a request. The returned String should be parsed with parseHeader()
	 *
	 * @param terminator
	 * @return String of the raw response
	 * @throws IOException
	 * @throws AntivirusException
	 */
	private String getHeader(String terminator) throws IOException, AntivirusException
	{
		byte[] endofheader = terminator.getBytes(StandardCharsetsUTF8);
		byte[] buffer = new byte[stdReceiveLength];

		int n;
		int offset = 0;
		//stdReceiveLength-offset is replaced by '1' to not receive the next (HTTP) header.
		while ((offset < stdReceiveLength) && ((n = in.read(buffer, offset, 1)) != -1))
		{ // first part is to secure against DOS
			offset += n;
			if (offset > endofheader.length + 13)
			{ // 13 is the smallest possible message "ICAP/1.0 xxx "
				byte[] lastBytes = Arrays.copyOfRange(buffer, offset - endofheader.length, offset);
				if (Arrays.equals(endofheader, lastBytes))
				{
					return new String(buffer, 0, offset, StandardCharsetsUTF8);
				}
			}
		}
		throw new AntivirusException("Error in getting the header from the response");
	}

	/**
	 * Given a raw response header as a String, it will parse through it and return a HashMap of the result
	 *
	 * @param response A raw response header as a String.
	 * @return HashMap of the key-value pairs of the response
	 */
	private Map<String, String> parseHeader(String response)
	{
		Map<String, String> headers = new HashMap<>();

		/****SAMPLE:****
		 * ICAP/1.0 204 Unmodified
		 * Server: C-ICAP/0.1.6
		 * Connection: keep-alive
		 * ISTag: CI0001-000-0978-6918203
		 */
		// The status code is located between the first 2 whitespaces.
		// Read status code
		int x = response.indexOf(' ', 0);
		int y = response.indexOf(' ', x + 1);
		String statusCode = response.substring(x + 1, y);
		headers.put(STATUS_CODE, statusCode);

		/** Each line in the sample is ended with "\r\n".
		 * When (i+2 == response.length()) The end of the header has been reached.
		 * The +=2 is added to skip the "\r\n".
		 * Read headers
		 **/
		int i = response.indexOf(LINETERMINATOR, y);
		i += 2;
		while (i + 2 != response.length() && response.substring(i).contains(":"))
		{
			int n = response.indexOf(':', i);
			String key = response.substring(i, n);

			n += 2;
			i = response.indexOf(LINETERMINATOR, n);
			String value = response.substring(n, i);

			headers.put(key, value);
			i += 2;
		}

		return headers;
	}

	/**
	 * Sends a String through the socket connection.
	 * Used for sending ICAP/HTTP headers.
	 *
	 * @param requestHeader
	 * @throws IOException
	 */
	private void sendString(String requestHeader) throws IOException
	{
		out.write(requestHeader.getBytes(StandardCharsetsUTF8));
	}

	/**
	 * Sends bytes of data from a byte-array through the socket connection.
	 * Used to send filedata.
	 *
	 * @param chunk The byte-array to send.
	 * @throws IOException
	 */
	private void sendBytes(byte[] chunk) throws IOException
	{
		for (int i = 0; i < chunk.length; i++)
		{
			out.write((char)chunk[i]);
		}
	}

	/**
	 * Terminates the socket connecting to the ICAP server.
	 *
	 * @throws IOException
	 */
	public void disconnect() throws IOException
	{
		if (client != null)
		{
			client.close();
		}
	}

	public StringBuilder getFailureReason()
	{
		return failureReason;
	}

	/**
	 * Given the response from the server interpret each possible response code
	 *
	 * @param responseMap The response packet as a key value pair map.
	 * @throws AntivirusException
	 */
	private Boolean interpretStatusCode(Map<String, String> responseMap) throws AntivirusException
	{
		String statusString = responseMap.get(STATUS_CODE);
		if (!StringUtil.isNullEmptyOrBlank(statusString))
		{
			int statusCode = Integer.parseInt(statusString);
			switch (statusCode)
			{
				case 100: //Continue transfer for the rest of the file
					logger.info(SERVER_RESPONSE + statusCode + " - continue transfer.");
					return true;
				case 200:
					//if the response contains the "Method" key it means it's a response for an OPTIONS request
					//else the request has been successfully executed but the file may be infected
					//we must check for the extension headers if a threat has been found
					//if they don't exists it means that the file was sent but the antivirus didn't actually scan it
					if (responseMap.containsKey("Methods"))
					{
						logger.info(SERVER_RESPONSE + statusCode + " received for get OPTIONS method");
						String tempString = responseMap.get("Preview");
						if (tempString != null)
						{
							int serverPreviewSize = Integer.parseInt(tempString);
							//the preview size will be set from the server or from the configuration file only if it is smaller than what the server returned
							if (this.stdPreviewSize == -1 || this.stdPreviewSize > serverPreviewSize)
								this.stdPreviewSize = serverPreviewSize;
							logger.info(
								"Preview size received from server: " + serverPreviewSize + ". Using preview size: "
									+ stdPreviewSize);
						}
						else
						{
							throw new AntivirusException("Could not get preview size from server");
						}
						return true;
					}
					else
					{
						logger.info(SERVER_RESPONSE + statusCode
							+ " - request successfully processed by server, checking for threats...");
						failureReason = new StringBuilder();
						for (String key : responseMap.keySet())
							if (key.startsWith("X-"))
								failureReason.append(key + ": " + responseMap.get(key));
						logger.error("Infection found: " + failureReason.toString());
						return false;
					}
				case 204: //file is clean
					logger.info(SERVER_RESPONSE + statusCode + " - file is clean.");
					return true;
				case 400:
					throw new AntivirusException("400: Bad request");
				case 404:
					throw new AntivirusException("404: ICAP Service not found");
				case 405: //e.g. RESPMOD requested for service that supports only REQMOD
					throw new AntivirusException("405: Method not allowed for service");
				case 408: //ICAP server gave up waiting for a request from an ICAP client
					throw new AntivirusException("408: Request timeout");
				case 500: //Error on the ICAP server, such as "out of disk space"
					throw new AntivirusException("500: Server error");
				case 501: // when the ICAP server does not have implemented the RESPMOD option
					throw new AntivirusException("501: Method not implemented");
				case 502: //This is an ICAP proxy and proxying produced an error
					throw new AntivirusException("502: Bad Gateway");
				case 503: //The ICAP server has exceeded a maximum connection limit associated with this service
					throw new AntivirusException("503: Service overloaded");
				case 505:
					throw new AntivirusException("505: ICAP version not supported by server");
				default:
					throw new AntivirusException("Server returned unknown status code:" + statusCode);
			}
		}
		else
			throw new AntivirusException("Server didn't return a status code");

	}
}
