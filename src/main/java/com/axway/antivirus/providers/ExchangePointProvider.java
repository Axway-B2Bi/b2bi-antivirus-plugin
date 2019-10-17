// Copyright Axway Software, All Rights Reserved.
// Please refer to the file "LICENSE" for further important copyright
// and licensing information.  Please also refer to the documentation
// for additional copyright notices.
package com.axway.antivirus.providers;

import com.cyclonecommerce.collaboration.transport.ExchangePoint;

public interface ExchangePointProvider
{
	ExchangePoint get(String epId);
}
