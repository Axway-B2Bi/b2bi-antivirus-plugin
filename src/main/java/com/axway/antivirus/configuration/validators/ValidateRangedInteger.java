// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.configuration.validators;

public class ValidateRangedInteger implements ValidationStrategy
{
	int minSize;
	int maxSize;

	/**
	 * @param minValue The minimum value an int input can have
	 * @param maxValue The maximum value an int input can have
	 */
	public ValidateRangedInteger(int minValue, int maxValue)
	{
		this.minSize = minValue;
		this.maxSize = maxValue;

	}

	/**
	 * @param input The String input to be validated
	 * @return a Boolean value if the input is valid or not
	 */
	@Override
	public boolean validate(String input)
	{
		try
		{
			int value = Integer.parseInt(input);
			return value > minSize && value <= maxSize;
		}
		catch (NumberFormatException nfe)
		{
			return false;
		}
	}
}
