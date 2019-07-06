
# https://www.sysadmins.lv/blog-en/introducing-to-certificate-enrollment-apis-part-2-creating-offline-requests.aspx 

$TS = $(get-date -format yyyyMMddHHmmss) 
$CN = "junk$TS" 
$CNFN = "My automated offline CSR for $CN" 

# DN first 
$SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName 
$SubjectDN.Encode("CN=$CN, OU=PKI DEV, O=Some Organisation, C=BE", 0x0) 

# SANs 
$SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames 
$IANs = New-Object -ComObject X509Enrollment.CAlternativeNames 

$CN, "$CN.example.com" | ForEach-Object { 
    # instantiate a IAlternativeName object 
    $IAN = New-Object -ComObject X509Enrollment.CAlternativeName 
    # initialize the object by using current element in the pipeline 
    $IAN.InitializeFromString(0x3,$_) 
    # add created object to an object collection of IAlternativeNames 
    $IANs.Add($IAN) 
} 
# finally, initialize SAN extension from a collection of alternative names: 
$SAN.InitializeEncode($IANs) 

# make a key 
$PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey -Property @{ 
    ProviderName = "Microsoft RSA SChannel Cryptographic Provider" 
    MachineContext = $true 
    Length = 2048 
    KeySpec = 1 
    KeyUsage = [int][Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment 
} 
$PrivateKey.Create() 

# key usage above is not carried over, so we need to do the x509 KU here 
$KeyUsage = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage 
$KeyUsage.InitializeEncode([int][Security.Cryptography.X509Certificates.X509KeyUsageFlags]"DigitalSignature,KeyEncipherment") 
$KeyUsage.Critical = $true 

# extensions for extended key usage and OID 
# create appropriate interface objects 
$EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage 
$OIDs = New-Object -ComObject X509Enrollment.CObjectIDs 
"Server Authentication", "Client Authentication" | ForEach-Object { 
    # transform current element to an Oid object. This is necessary to retrieve OID value. 
    # this step is not required when you pass OID values directly. 
    $netOid = New-Object Security.Cryptography.Oid $_ 
    # instantiate a IObjectID object for current element. 
    $OID = New-Object -ComObject X509Enrollment.CObjectID 
    # initialize the object with current enhanced key usage 
    $OID.InitializeFromValue($netOid.Value) 
    # add the object to an object collection 
    $OIDs.Add($OID) 
} 
# when all EKUs are processed, initialized the IX509ExtensionEnhancedKeyUsage with the IObjectIDs collection 
$EKU.InitializeEncode($OIDs) 

# now make the pkcs10 object 
$PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10 

# we are making a non-MS or "offline" CSR, so we pick an appropriate init method for the object 
# 0x2 argument for Context parameter indicates that the request is intended for computer (or machine context). 
# strTemplateName parameter is optional and we pass just empty string. 
$PKCS10.InitializeFromPrivateKey(0x2,$PrivateKey,"") 

# the request is not signed yet, so we will add subject information and certificate extension information: 
$PKCS10.Subject = $SubjectDN 
$PKCS10.X509Extensions.Add($SAN) 
$PKCS10.X509Extensions.Add($EKU) 
$PKCS10.X509Extensions.Add($KeyUsage) 

# Once we added all required information, we are ready to create signed request through enrollment interface IX509Enrollment. 
# The following commands will instantiate and initialize IX509Enrollment object: 
# instantiate IX509Enrollment object 
$Request = New-Object -ComObject X509Enrollment.CX509Enrollment 
# provide certificate friendly name: 
$Request.CertificateFriendlyName = $CNFN 
# initialize the object from PKCS#10 object: 
$Request.InitializeFromRequest($PKCS10) 

# The request is now ready to be signed. 
# Normally for all new requests we will use XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3 argument. 
$Base64 = $Request.CreateRequest(0x3) 
#Set-Content $path -Value $Base64 -Encoding Ascii 
Write-Output $Base64 

# Once the request is generated, a copy of request object is stored in Certificate Enrollment Requests container in certificate store. 
# so we have to clear up... 
#$Thumb = $(Get-ChildItem Cert:\LocalMachine\REQUEST | where-object -Property FriendlyName -eq "$CNFN" | Select-Object -Property Thumbprint) 
$Thumb = Get-ChildItem Cert:\LocalMachine\REQUEST | where-object -Property FriendlyName -eq "$CNFN" 
$TH = $Thumb.Thumbprint 
Remove-Item -path Cert:\localmachine\REQUEST\$TH -DeleteKey 
  
