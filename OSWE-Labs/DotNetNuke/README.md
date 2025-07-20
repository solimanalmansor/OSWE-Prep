# DotNetNuke Cookie Deserialization RCE
This module covered the analysis and exploitation of a deserialization vulnerability in the .NET DNN application.These types of vulnerabilities are most often found in PHP or Java based applications.However, as we’ve demonstrated in this module, .NET applications can suffer fromthis vulnerability class as well, and the impact can be significant.
## Introduction
Serialization is the process of converting structured data into a format that can be stored in a file or database, or transmitted over a network. Typically, serialization involves a producer and a consumer of the serialized data structure or object.
We will focus on the `XMLSerializer` class, as it is directly related to the vulnerability covered in this module. As the name suggests, the `XMLSerializer` class stores the state of an object in XML format.

**[Limitations:](https://learn.microsoft.com/en-us/dotnet/standard/serialization/introducing-xml-serialization#items-that-can-be-serialized)**
- `XmlSerializer` class can only serialize public fields and property values of an object.
- `XmlSerializer` class supports a narrow set of object types, primarily due to the fact that it cannot serialize abstract classes:
  - `XmlElement` objects.
  - `XmlNode` objects.
  - `DataSet` objects.
- the type of the object being serialized must always be known to the `XmlSerializer` instance at runtime.
## Vulnerability Analysis
### Vulnerability Overview
The vulnerability lies in the handling of the `DNNPersonalization` cookie, which is associated with user profiles. Notably, it can be exploited without requiring authentication. The entry point for the vulnerability is the `LoadProfile` function within the `DotNetNuke.dll` module.

The `LoadProfile` function in the `DotNetNuke.Services.Personalization.PersonalizationController` namespace is triggered when a user visits a non-existent page in a DNN web application. It checks for the `DNNPersonalization` cookie and, if present, passes its value to the `DeserializeHashTableXml` function. 

```c#
		HttpContext httpContext = HttpContext.Current;
		if (httpContext != null && httpContext.Request.Cookies["DNNPersonalization"] != null)
		{
			text = httpContext.Request.Cookies["DNNPersonalization"].Value;
		}
	}
	personalizationInfo.Profile = (string.IsNullOrEmpty(text) ? new Hashtable() : Globals.DeserializeHashTableXml(text));
	return personalizationInfo;
}
```

This function then calls `DeSerializeHashtable`, using the hardcoded string `"profile"` as a second parameter.

```c#
    public static Hashtable DeserializeHashTableXml(string Source)
		{
			return XmlUtils.DeSerializeHashtable(Source, "profile");
		}
```

Inside `DeSerializeHashtable`, the process involves extracting the object type from the XML, creating an `XmlSerializer` based on it, and deserializing the user-controlled data. Critically, no type validation is performed during deserialization, making it a likely vector for exploitation.

```c#
    public static Hashtable DeSerializeHashtable(string xmlSource, string rootname)
		{
			Hashtable hashtable = new Hashtable();
			if (!string.IsNullOrEmpty(xmlSource))
			{
				try
				{
					XmlDocument xmlDocument = new XmlDocument();
					xmlDocument.LoadXml(xmlSource);
					foreach (object obj in xmlDocument.SelectNodes(rootname + "/item"))
					{
						XmlElement xmlElement = (XmlElement)obj;
						string attribute = xmlElement.GetAttribute("key");
						string attribute2 = xmlElement.GetAttribute("type");
						XmlSerializer xmlSerializer = new XmlSerializer(Type.GetType(attribute2));
						XmlTextReader xmlReader = new XmlTextReader(new StringReader(xmlElement.InnerXml));
						hashtable.Add(attribute, xmlSerializer.Deserialize(xmlReader));
					}
				}
				catch (Exception)
				{
				}
			}
			return hashtable;
		}
```

**Refrences:** https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf

### Manipulation of Assembly Attributes for Debugging
Debugging .NET web applications is often complicated by runtime optimizations that prevent setting breakpoints or inspecting local variables. This is because most assemblies are compiled in Release mode, with attributes like:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
To improve the debugging experience, this can be changed to:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations | DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints | DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Via right clicking the module name and then choosing `Edit Assembly Attributes (C#)`

This modification can be done using dnSpy. It's crucial to edit the correct assembly — in this case, `DotNetNuke.dll` located at:

```
C:\inetpub\wwwroot\dotnetnuke\bin\DotNetNuke.dll
```
However, IIS loads assemblies from a temporary location:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\dotnetnuke\
```
