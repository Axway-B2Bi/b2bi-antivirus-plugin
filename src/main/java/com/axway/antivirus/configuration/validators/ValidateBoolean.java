// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.configuration.validators;

public class ValidateBoolean implements ValidationStrategy
{
	/**
	 * @param input A String input to be validated
	 * @return a Boolean value if the input is either <code>true</code> or <code>false</code>
	 */
	@Override
	public boolean validate(String input)
	{
		return input.equalsIgnoreCase("true") || input.equalsIgnoreCase("false");
	}
}
