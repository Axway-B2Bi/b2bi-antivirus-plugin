package com.axway.antivirus.providers;

import com.cyclonecommerce.collaboration.transport.ExchangePoint;

public interface ExchangePointProvider
{
	ExchangePoint get(String epId);
}
