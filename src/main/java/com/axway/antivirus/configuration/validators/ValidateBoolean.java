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
