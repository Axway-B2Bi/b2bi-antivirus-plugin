package com.axway.antivirus.configuration.validators;

import com.axway.util.StringUtil;

public class ValidateRangedString implements ValidationStrategy
{
	int maxSize;

	/**
	 * @param maxSize The maximum length a String input can have
	 */
	public ValidateRangedString(int maxSize)
	{
		this.maxSize = maxSize;
	}

	/**
	 * @param input A String input to be validated
	 * @return a Boolean value if the input is not empty and the length is less or equal than the <code>maxSize</code>
	 */
	@Override
	public boolean validate(String input)
	{
		return !StringUtil.isNullEmptyOrBlank(input) && input.length() <= maxSize;
	}
}
