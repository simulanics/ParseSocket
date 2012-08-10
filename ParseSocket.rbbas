#tag Class
Protected Class ParseSocket
Inherits HTTPSecureSocket
	#tag Event
		Function AuthenticationRequired(Realm As String, Headers As InternetHeaders, ByRef Name As String, ByRef Password As String) As Boolean
		  // NOT USED
		  // So it won't be visible into a subclass by adding this comment
		End Function
	#tag EndEvent

	#tag Event
		Sub Error(code as integer)
		  // A socket error is not a content error
		  RaiseEvent Error( code, 0, False, "" )
		End Sub
	#tag EndEvent

	#tag Event
		Sub HeadersReceived(headers as internetHeaders, httpStatus as integer)
		  // NOT USED
		  // So it won't be visible into a subclass by adding this comment
		End Sub
	#tag EndEvent

	#tag Event
		Sub PageReceived(url as string, httpStatus as integer, headers as internetHeaders, content as string)
		  // Content is a JSON object
		  // The URL represents which function is returning the content
		  
		  try
		    Dim J As new JSONItem(content)
		    
		    // See if this request has a "sessionToken" key
		    if j.HasName("sessionToken") then
		      SessionToken = j.Value("sessionToken") 'Store the SessionToken, so the user can do anything without re-login
		      if j.HasName("objectId") then
		        UserObjectID = j.Value("objectId") 'Store the UserObjectID so the user's data can be easily captured
		      end if
		    end if
		    // If we have none of the above ( SessionToken or UserObjectID ) then the user is not logged in.
		    // It would be required to eighter login or register for further use.
		    
		    // Here we check for error (see Error types note)
		    // The responseReceived event won't be fired if an error is found.
		    
		    
		    // pass the response to the subclass if there was no error
		    RaiseEvent ResponseReceived( httpStatus, j, url, headers )
		    
		    
		    
		  catch err As JSONException
		    'Catch the JSON exception before it crashes the program
		    'We pass the error to the subclass to be handled accordingly
		    RaiseEvent Error(0, httpStatus, True, "Reveived data could not be read.")
		  end try
		End Sub
	#tag EndEvent

	#tag Event
		Function ProxyAuthenticationRequired(Realm As String, Headers As InternetHeaders, ByRef Name As String, ByRef Password As String) As Boolean
		  // NOT USED
		  // So it won't be visible into a subclass by adding this comment
		End Function
	#tag EndEvent


	#tag Method, Flags = &h1000
		Sub Constructor()
		  // Calling the overridden superclass constructor.
		  // Note that this may need modifications if there are multiple constructor choices.
		  // Possible constructor calls:
		  // Constructor() -- From HTTPSecureSocket
		  // Constructor() -- From TCPSocket
		  // Constructor() -- From SocketCore
		  Super.Constructor
		  
		  // Default settings
		  Secure = True
		  DefaultPort = 443
		  Port = 443
		  ConnectionType = me.TLSv1
		  
		  
		  // Set yield true for asynchronymous requests
		  Yield = True
		  
		  // DON'T EDIT THIS, PARSE USES TLS VERSION 1.0 AND PORT 443.
		  // SECURE MUST BE TRUE AND TO MAKE SURE YOUR APP KEEPS RESPONDING TO EVENTS, LEAVE THE YIELD PROPERTY TO TRUE !
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function GetCurrentUser() As Boolean
		  // Retrieve a user from Parse
		  // Requires a GET request
		  // https://www.parse.com/docs/rest#users-retrieving
		  // Will return false if the user was not logged in
		  
		  // A user can only be retrieved if he was logged in and got a SessionToken
		  // ParseSocket stores the SessionToken, while the user is active.
		  
		  if UserObjectID <> "" then
		    
		    // Generate the url
		    Dim URL As String
		    URL = me.DOMAIN + me.PARSE_USERS_OBJECT + UserObjectID
		    
		    // Set api headers
		    me.ClearRequestHeaders
		    me.SetRequestHeader me.PARSE_HEADER_APP_ID, me.APP_ID
		    me.SetRequestHeader me.PARSE_HEADER_REST_API_KEY, me.APP_REST_API_KEY
		    me.SetRequestHeader "Content-Type", me.CONTENT_TYPE_JSON
		    
		    // Make GET request to Parse for the Current user, if there is any logged in or just registered.
		    me.Get( URL )
		    
		    Return True 'Indicate that this call has been made (can still get an error though).
		    
		  else 'No UserObjectID found
		    Return False
		  end if
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Login(UserName As String, Password As String)
		  // Log a user in
		  // Requires a GET request with username=&password=
		  // https://www.parse.com/docs/rest#users-login
		  
		  // Set api headers
		  me.ClearRequestHeaders
		  me.SetRequestHeader me.PARSE_HEADER_APP_ID, me.APP_ID
		  me.SetRequestHeader me.PARSE_HEADER_REST_API_KEY, me.APP_REST_API_KEY
		  me.SetRequestHeader "Content-Type", me.CONTENT_TYPE_JSON
		  
		  // Generate a valid URL 
		  Dim URL As String 
		  URL = me.DOMAIN + PARSE_LOGIN + "?username=" + EncodeURLComponent(UserName) + "&password=" + EncodeURLComponent(SecurePassword(Password))
		  
		  // Make the request
		  me.Get(  URL )
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function QueryClass(ClassName As String, Query As JSONItem = nil) As Boolean
		  // Makes a query to the classes api
		  // Requires a GET request
		  // Without the "Query" https://www.parse.com/docs/rest#queries-basic
		  // With the "Query" https://www.parse.com/docs/rest#queries-constraints
		  
		  'Make sure the class name is not blank, otherwise we get an error
		  if ClassName = "" then Return False
		  
		  // Create the request URL
		  Dim URL As String
		  URL = me.DOMAIN + me.PARSE_CLASSES_OBJECT + ClassName
		  
		  // Set api headers
		  me.ClearRequestHeaders
		  me.SetRequestHeader me.PARSE_HEADER_APP_ID, me.APP_ID
		  me.SetRequestHeader me.PARSE_HEADER_REST_API_KEY, me.APP_REST_API_KEY
		  me.SetRequestHeader "Content-Type", me.CONTENT_TYPE_JSON
		  
		  // check if the query is a JSONItem or nil
		  if Query <> nil then 'Query has data so we append "where=[JSONItem]" to the GET
		    
		    Query.Compact = True 'Make the JSON string as small as possible
		    URL = URL + "?where=" + EncodeURLComponent(Query.ToString)
		    
		  end if
		  
		  // Make the GET request
		  me.Get( URL )
		  
		  // Return true, to indicate that the request was made
		  Return True
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub QueryUsers(Query As JSONItem = nil)
		  // Register new account on Parse
		  // Requires GET request
		  // https://www.parse.com/docs/rest#users-querying
		  
		  // Set api headers
		  me.ClearRequestHeaders
		  me.SetRequestHeader me.PARSE_HEADER_APP_ID, me.APP_ID
		  me.SetRequestHeader me.PARSE_HEADER_REST_API_KEY, me.APP_REST_API_KEY
		  me.SetRequestHeader "Content-Type", me.CONTENT_TYPE_JSON
		  
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub RegisterUser(UserName As String, Password As String, Email As String)
		  // Register new account on Parse
		  // Requires POST request
		  // https://www.parse.com/docs/rest#users-signup
		  
		  // Set api headers
		  me.ClearRequestHeaders
		  me.SetRequestHeader me.PARSE_HEADER_APP_ID, me.APP_ID
		  me.SetRequestHeader me.PARSE_HEADER_REST_API_KEY, me.APP_REST_API_KEY
		  me.SetRequestHeader "Content-Type", me.CONTENT_TYPE_JSON
		  
		  // Create JSON request content
		  Dim j As new JSONItem
		  j.Value("username") = UserName
		  j.Value("password") = SecurePassword(Password) //does md5 hash on the password
		  j.Value("email") = Email
		  j.Compact = True // make the data free of whitespace and tabs
		  
		  // Set POST content
		  me.SetPostContent j.ToString, CONTENT_TYPE_JSON
		  
		  // Make POST request
		  me.SendRequest "POST", me.DOMAIN + me.PARSE_USERS
		  
		  // Response will be:
		  // Status: 201 Created
		  // Location: https://api.parse.com/1/users/[userobject]
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function SecurePassword(Password As String) As String
		  // For the sake of safety, when using this on an insecure connection it won't be secure. 
		  // The connection with Parse.com is TLS encrypted, that means we don't have to worry about using MD5 or SHA1 (or any other)
		  // Just for the better, normally you would want to hash any string which won't be retrieved in any way.
		  Return Lowercase( EncodeHex( MD5(password), false ) )
		  
		  // Parse.com won't send you the password over the internet back, you can login and get back a SessionToken with an objectId
		  // That means it's much more secure to use.
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub SendFile(File As FolderItem, ContentType As String)
		  // Send a File with the Parse rest api
		  // Requires a POST request
		  // https://www.parse.com/docs/rest#files-uploading
		  
		  // Set app headers
		  me.ClearRequestHeaders
		  me.SetRequestHeader PARSE_HEADER_APP_ID, APP_ID
		  me.SetRequestHeader PARSE_HEADER_REST_API_KEY, APP_REST_API_KEY
		  me.SetRequestHeader "Content-Type", me.CONTENT_TYPE_JSON
		  
		  // TODO ::::::::::::
		  // Set the POST content (add the file to the request)
		  
		  
		  // Do post request
		  me.SendRequest "POST", DOMAIN + PARSE_FILES_OBJECT + File.Name
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function UpdateUser(UserFields As JSONItem) As Boolean
		  // Updates a user's JSON stored fields
		  // Requires a PUT request
		  // https://www.parse.com/docs/rest#users-updating
		  // Will return false if the user was not logged in
		  
		  // See if there is an active session
		  if SessionToken <> "" and UserObjectID <> "" then 
		    
		    // Set api headers
		    me.ClearRequestHeaders
		    me.SetRequestHeader me.PARSE_HEADER_APP_ID, me.APP_ID
		    me.SetRequestHeader me.PARSE_HEADER_REST_API_KEY, me.APP_REST_API_KEY
		    me.SetRequestHeader me.PARSE_HEADER_SESSION_TOKEN, me.SessionToken
		    me.SetRequestHeader "Content-Type", me.CONTENT_TYPE_JSON
		    
		    // Make the PUT request
		    me.SendRequest "PUT", me.DOMAIN + me.PARSE_USERS_OBJECT + UserObjectID
		    
		    // Return true to indicate that the User was alread logged in.
		    Return True
		    
		  else 'Not logged in
		    Return False
		  end if
		End Function
	#tag EndMethod


	#tag Hook, Flags = &h0
		Event Error(Code As Integer, HTTPStatus As Integer, IsParseError As Boolean, ParseErrorMessage As String)
	#tag EndHook

	#tag Hook, Flags = &h0
		Event ResponseReceived(Status As Integer, Content As JSONItem, URL As String, Headers As InternetHeaders)
	#tag EndHook


	#tag Note, Name = Error types
		Once the error event has been fired, the result of the last request won't be given. You only get this error event to handle it the simple way.
		The ERROR event will be raised once a HTTPSecureSocket error is found and when there is an error with the api data.
		
		Each property of the Error event is explained here:
		Code As Integer                           - This is the code you recieve from the HTTPSecureSocket super class. It's the same as normal.
		HTTPStatus As Integer,            - This is the http status code, 200 will be the same as "OK" (and means no error in http)
		IsParseError As Boolean,           - If this is true then, parse returned an error in JSON format. Some properties might be missing or the request was not right.
		ParseErrorMessage As String   - This is the error message that parse.com returned. You won't get if from the JSONI result but in this event only.
	#tag EndNote

	#tag Note, Name = Parse.com REST API INFO
		
		Parse.com provides a REST api for easy data storage on the cloud.
		This class provides all REAL Basic applications (including web edition, at the time of writing this) with a simple class to make requests to parse.com.
		It's secure, pretty easy (once you know real basic) and very well documented inside the code (methods, events etc..)
		
		This class has been written by Derk Jochems (sworteu) from the Netherlands.
		It was made in order to make the use of Parse.com much more easy. 
		
		This class works on Web Edition and Desktop of real studio.
		
	#tag EndNote


	#tag Property, Flags = &h0
		#tag Note
			Add your APP ID from your parse.com account here.
			You can set it when you create the class, but make sure it's there before you use the ParseSocket !
		#tag EndNote
		APP_ID As String = "CHnSJU33zR9cchmLwMCi6intfu52ieTy9GgeTAyM"
	#tag EndProperty

	#tag Property, Flags = &h0
		#tag Note
			Add your REST API KEY from your parse.com account here.
			You can set it when you create the class, but make sure it's there before you use the ParseSocket !
		#tag EndNote
		APP_REST_API_KEY As String = "59gRFQNEH5uPRFsiO7WU2YWqF9oI6jR51N0QkkOv"
	#tag EndProperty

	#tag Property, Flags = &h21
		#tag Note
			The user token, which is used for requests after the user was created or logged in.
			
			This is returned after creating a new user like this:
			{
			"createdAt": "2011-11-07T20:58:34.448Z",
			"objectId": "g7y9tkhB7O",
			"sessionToken": "pnktnjyb996sj4p156gjtp4im"
			}
		#tag EndNote
		Private SessionToken As String
	#tag EndProperty

	#tag Property, Flags = &h21
		#tag Note
			The objectID represents an object or user
			UserObjectID represents a user
		#tag EndNote
		Private UserObjectID As String
	#tag EndProperty


	#tag Constant, Name = CONTENT_TYPE_JSON, Type = String, Dynamic = False, Default = \"application/json", Scope = Private
	#tag EndConstant

	#tag Constant, Name = DOMAIN, Type = String, Dynamic = False, Default = \"https://api.parse.com", Scope = Private
	#tag EndConstant

	#tag Constant, Name = PARSE_CLASSES_OBJECT, Type = String, Dynamic = False, Default = \"/1/classes/", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_FILES_OBJECT, Type = String, Dynamic = False, Default = \"/1/files/", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_HEADER_APP_ID, Type = String, Dynamic = False, Default = \"X-Parse-Application-Id", Scope = Private
	#tag EndConstant

	#tag Constant, Name = PARSE_HEADER_REST_API_KEY, Type = String, Dynamic = False, Default = \"X-Parse-REST-API-Key", Scope = Private
	#tag EndConstant

	#tag Constant, Name = PARSE_HEADER_SESSION_TOKEN, Type = String, Dynamic = False, Default = \"X-Parse-Session-Token", Scope = Private
	#tag EndConstant

	#tag Constant, Name = PARSE_INSTALLATIONS, Type = String, Dynamic = False, Default = \"/1/installations", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_INSTALLATIONS_OBJECT, Type = String, Dynamic = False, Default = \"/1/installations", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_LOGIN, Type = String, Dynamic = False, Default = \"/1/login", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_PASSWORD_RESET, Type = String, Dynamic = False, Default = \"/1/requestPasswordReset", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_PUSH, Type = String, Dynamic = False, Default = \"/1/push", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_ROLES, Type = String, Dynamic = False, Default = \"/1/roles", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_USERS, Type = String, Dynamic = False, Default = \"/1/users", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = PARSE_USERS_OBJECT, Type = String, Dynamic = False, Default = \"/1/users/", Scope = Protected
	#tag EndConstant


	#tag ViewBehavior
		#tag ViewProperty
			Name="APP_ID"
			Group="Behavior"
			InitialValue="CHnSJU33zR9cchmLwMCi6intfu52ieTy9GgeTAyM"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
		#tag ViewProperty
			Name="APP_REST_API_KEY"
			Group="Behavior"
			InitialValue="59gRFQNEH5uPRFsiO7WU2YWqF9oI6jR51N0QkkOv"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
		#tag ViewProperty
			Name="CertificateFile"
			Visible=true
			Group="Behavior"
			Type="FolderItem"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="CertificatePassword"
			Visible=true
			Group="Behavior"
			Type="String"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="CertificateRejectionFile"
			Visible=true
			Group="Behavior"
			Type="FolderItem"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="ConnectionType"
			Visible=true
			Group="Behavior"
			InitialValue="2"
			Type="Integer"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Index"
			Visible=true
			Group="ID"
			Type="Integer"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Left"
			Visible=true
			Group="Position"
			Type="Integer"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Name"
			Visible=true
			Group="ID"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Secure"
			Visible=true
			Group="Behavior"
			Type="Boolean"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Super"
			Visible=true
			Group="ID"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Top"
			Visible=true
			Group="Position"
			Type="Integer"
			InheritedFrom="HTTPSecureSocket"
		#tag EndViewProperty
	#tag EndViewBehavior
End Class
#tag EndClass
