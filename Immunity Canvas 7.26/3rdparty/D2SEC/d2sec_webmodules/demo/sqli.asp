<%@ Language=VBScript %>
<%
Dim aConnectionString

aConnectionString = "Provider=SQLOLEDB;Data Source=;Database=AdventureWorks;UID=sa; PWD=rootmeh;"

%>
<b>ASP</b>
<%

Dim conn,R,SQL,RecsAffected
Set conn=Server.CreateObject("ADODB.Connection")
conn.Mode=adModeReadWrite
conn.ConnectionString = aConnectionString
conn.Open

//pwn = request.querystring("pwn")
pwn = request.form("pwn")
DIM mySQL
mySQL = "SELECT AddressLine1 from Person.Address WHERE AddressID=" & pwn

DIM objRS
Set objRS = Server.CreateObject("ADODB.Recordset")
objRS.Open mySQL, conn

Response.Write "Resultats : [" & objRS("AddressLine1") & "] OUAY OUAY"
conn.Close
Set conn = Nothing

%>
