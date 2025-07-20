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
Via right clicking the module name and then choosing `Edit Assembly Attributes (C#)` and click `Compile`

This modification can be done using dnSpy. It's crucial to edit the correct assembly — in this case, `DotNetNuke.dll` located at:

```
C:\inetpub\wwwroot\dotnetnuke\bin\DotNetNuke.dll
```
However, IIS loads assemblies from a temporary location:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\dotnetnuke\
```
It's important to note that once the IIS worker process starts, it does not load assemblies directly from the DotNetNuke directory under the inetpub path. Instead, it copies the necessary modules to a temporary directory and loads them from there. To ensure IIS loads the edited module, simply restart the IIS service.
```
C:\Inetpub\wwwroot\dotnetnuke\bin> iisreset /noforce
```
### Debugging DotNetNuke Using dnSpy

To debug DNN properly, you need to attach your debugger (e.g., dnSpy) to the `w3wp.exe` process — the IIS worker process running the DNN instance. If `w3wp.exe` isn’t visible, simply visit the DNN site in a browser to trigger IIS to start it, then click `Refresh` in the `Attach` dialog.

After attaching, pause execution `Debug > BreakAll` and open `Debug > Windows > Modules` to view all loaded modules. Right-click any module and select `Open All Modules` to load them into the `Assembly Explorer`, once loaded, you can resume the proccess execution by clicking `Continue`.

From there, navigate to the `LoadProfile(int, int)` function in the `DotNetNuke.Services.Personalization.PersonalizationController` namespace within `DotNetNuke.dll`.
## Exploitation
### Payload Options

Since we're dealing with a deserialization vulnerability similar to the earlier examples, our current objective is to identify a suitable payload object for our exploit. This object must meet the following criteria:

1. It must execute code useful for our purposes.
2. It must exist within one of the assemblies already loaded by the DNN application.
3. It must be serializable using the `XmlSerializer` class.
4. It must conform to the XML structure expected by the vulnerable `DeSerializeHashtable` function.

#### FileSystemUtils PullFile Method
The `DotNetNuke.dll` assembly contains a `FileSystemUtils` class with a `PullFile` method, which can download files from a URL to the server — potentially useful for uploading a malicious ASPX shell. 

```c#
		public static string PullFile(string URL, string FilePath)
		{
			string result = "";
			try
			{
				WebClient webClient = new WebClient();
				webClient.DownloadFile(URL, FilePath);
			}
			catch (Exception ex)
			{
				FileSystemUtils.Logger.Error(ex);
				result = ex.Message;
			}
			return result;
		}
```

However, since `XmlSerializer` can only serialize public properties and fields (not methods), and `FileSystemUtils` exposes none that would invoke `PullFile`, it's not a viable payload object. As a result, an alternative approach is needed.

#### ObjectDataProvider Class
Muñoz and Mirosh revealed four .NET deserialization gadgets useful for exploitation, with the `ObjectDataProvider` class being the most versatile and used in their DNN exploit. According to official documentation, `ObjectDataProvider` wraps another object to act as a binding source—essentially an object providing data to UI elements.

Its power lies in allowing attackers to set the `MethodName` property to invoke any method on the wrapped object, while `MethodParameters` lets them pass arguments to that method. Importantly, since `MethodName` and `MethodParameters` are properties (not methods), `ObjectDataProvider` works within the serialization constraints of `XmlSerializer`. This makes it an ideal payload candidate for triggering arbitrary method calls during deserialization.
