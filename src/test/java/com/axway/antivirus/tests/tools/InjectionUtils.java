package com.axway.antivirus.tests.tools;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class InjectionUtils
{

	/**
	 * Injects a field value using reflection
	 *
	 * @param target the object to inject
	 * @param className the class of the object
	 * @param fieldName the name of the field to inject in the class
	 * @param value the value for the field
	 * @param <T> the type of the object to inject
	 * @throws SecurityException if the request is denied.
	 * @throws NoSuchFieldException if a field with the specified name is not found.
	 * @throws IllegalArgumentException if the specified object is not an
	 * instance of the class or interface declaring the underlying
	 * field (or a subclass or implementor thereof),
	 * or if an unwrapping conversion fails.
	 * @throws IllegalAccessException if this {@code Field} object
	 * is enforcing Java language access control and the underlying
	 * field is either inaccessible or final.
	 */
	public static <T> void injectField(final T target, final Class<T> className, final String fieldName,
		final Object value) throws SecurityException, NoSuchFieldException, IllegalArgumentException,
		IllegalAccessException
	{
		Field f;

		try
		{
			f = className.getDeclaredField(fieldName);
		}
		catch (final NoSuchFieldException e)
		{
			f = className.getSuperclass().getDeclaredField(fieldName);
		}

		f.setAccessible(true);

		Field modifiersField = Field.class.getDeclaredField("modifiers");
		modifiersField.setAccessible(true);
		modifiersField.setInt(f, f.getModifiers() & ~Modifier.FINAL);

		f.set(target, value);
	}

	/**
	 * @param target the object to inject
	 * @param targetClass the class of the object
	 * @param fieldClass the class of the field
	 * @param fieldName the field name from the class
	 * @param <T> the type of the object to inject
	 * @param <U> the type of the field
	 * @return the value of the field
	 * @throws SecurityException if the request is denied.
	 * @throws NoSuchFieldException if a field with the specified name is not found.
	 * @throws IllegalArgumentException if the specified object is not an
	 * instance of the class or interface declaring the underlying
	 * field (or a subclass or implementor thereof),
	 * or if an unwrapping conversion fails.
	 * @throws IllegalAccessException if this {@code Field} object
	 * is enforcing Java language access control and the underlying
	 * field is either inaccessible or final.
	 */
	public static <T, U> U getFieldValue(final T target, final Class<T> targetClass, final Class<U> fieldClass,
		final String fieldName) throws SecurityException, NoSuchFieldException, IllegalArgumentException,
		IllegalAccessException
	{

		final Field f = targetClass.getDeclaredField(fieldName);
		f.setAccessible(true);

		final Object result = f.get(target);
		return fieldClass.cast(result);
	}

	/**
	 * @param target the object to inject
	 * @param className the class of the object
	 * @param resultClass the class of the value returned by the injected method
	 * @param methodName the name of the method to inject
	 * @param <T> the type of the object to inject
	 * @param <U> the type returned by the injected method
	 * @return the value returned by the injected method
	 * @throws SecurityException if the request is denied.
	 * @throws NoSuchMethodException if a method with the specified name is not found.
	 * @throws IllegalArgumentException if the specified object is not an
	 * instance of the class or interface declaring the underlying
	 * field (or a subclass or implementor thereof),
	 * or if an unwrapping conversion fails.
	 * @throws IllegalAccessException if this {@code Field} object
	 * is enforcing Java language access control and the underlying
	 * field is either inaccessible or final.
	 * @throws InvocationTargetException if the underlying method throws an exception.
	 */
	public static <T, U> U invokePrivateMethod(final T target, final Class<T> className, final Class<U> resultClass,
		final String methodName) throws SecurityException, NoSuchMethodException, IllegalArgumentException,
		IllegalAccessException, InvocationTargetException
	{

		final Method m = className.getDeclaredMethod(methodName);
		m.setAccessible(true);
		final Object result = m.invoke(target);

		return resultClass.cast(result);
	}

	/**
	 * @param target the object to inject
	 * @param className the class of the object
	 * @param resultClass the type of the value returned by the injected method
	 * @param methodName the name of the method to inject
	 * @param argTypes the types of the arguments of the method to inject
	 * @param args the list of arguments to inject
	 * @param <T> the type of the object to inject
	 * @param <U> the type of the result
	 * @return the value returned by the injected method
	 * @throws SecurityException if the request is denied.
	 * @throws NoSuchMethodException if a method with the specified name is not found.
	 * @throws IllegalArgumentException if the specified object is not an
	 * instance of the class or interface declaring the underlying
	 * field (or a subclass or implementor thereof),
	 * or if an unwrapping conversion fails.
	 * @throws IllegalAccessException if this {@code Field} object
	 * is enforcing Java language access control and the underlying
	 * field is either inaccessible or final.
	 * @throws InvocationTargetException if the underlying method throws an exception.
	 */
	public static <T, U> U invokePrivateMethodWithArguments(final T target, final Class<T> className,
		final Class<U> resultClass, final String methodName, final Class<?>[] argTypes, final Object[] args) throws
		RuntimeException, NoSuchMethodException, IllegalAccessException, InvocationTargetException
	{

		final Method m = className.getDeclaredMethod(methodName, argTypes);
		m.setAccessible(true);
		try
		{
			final Object result = m.invoke(target, args);
			return resultClass.cast(result);
		}
		catch (final InvocationTargetException e)
		{
			if (e.getCause() instanceof RuntimeException)
			{
				throw (RuntimeException)e.getCause();
			}
			else
			{
				throw e;
			}
		}

	}
}
