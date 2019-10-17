// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.configuration.validators;

public class ValidateRangedLong implements ValidationStrategy
{
	long minSize;
	long maxSize;

	/**
	 * @param minValue The minimum value a long input can have
	 * @param maxValue The maximum value a long input can have
	 */
	public ValidateRangedLong(long minValue, long maxValue)
	{
		this.minSize = minValue;
		this.maxSize = maxValue;

	}

	/**
	 * @param input A String input to be validated
	 * @return a Boolean value if the input is valid or not
	 */
	@Override
	public boolean validate(String input)
	{
		try
		{
			long value = Long.parseLong(input);
			return value > minSize && value <= maxSize;
		}
		catch (NumberFormatException nfe)
		{
			return false;
		}
	}
}
