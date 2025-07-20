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
